//! Classification of Docker disk-usage items (pure; no engine access).
//!
//! | Item                                   | Class     |
//! |----------------------------------------|-----------|
//! | Running/paused/restarting container    | Protected |
//! | Stopped container                      | Review    |
//! | Image used by a running container      | Protected |
//! | Image used only by stopped containers  | Review    |
//! | Dangling (untagged) unused image       | Safe      |
//! | Tagged unused image                    | Review    |
//! | Volume in use                          | Protected |
//! | Unused volume                          | Protected, or Review if volume cleanup is enabled |
//! | Unused build cache (one aggregate item)| Safe      |

use std::collections::{BTreeMap, HashMap};

use rustclean_core::SafetyClass;
use serde_json::Value;

use crate::KindTotals;

/// Ordered by removal order: containers before the images and volumes
/// they reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    Container,
    Image,
    Volume,
    BuildCache,
}

impl ItemKind {
    pub fn label(self) -> &'static str {
        match self {
            ItemKind::Container => "Containers",
            ItemKind::Image => "Images",
            ItemKind::Volume => "Volumes",
            ItemKind::BuildCache => "Build cache",
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            ItemKind::Container => "container",
            ItemKind::Image => "image",
            ItemKind::Volume => "volume",
            ItemKind::BuildCache => "build-cache",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerItem {
    pub kind: ItemKind,
    /// Container/image ID, volume name, or "unused" for the build cache.
    pub id: String,
    pub name: String,
    pub detail: String,
    /// Estimated bytes freed by removing this item.
    pub size: u64,
    pub class: SafetyClass,
    pub reason: Option<String>,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn n(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or(-1)
}

fn bytes(x: i64) -> u64 {
    u64::try_from(x).unwrap_or(0)
}

fn items<'a>(usage: &'a Value, key: &str) -> &'a [Value] {
    usage
        .get(key)
        .and_then(|u| u.get("Items"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn totals(usage: &Value, key: &str) -> KindTotals {
    let u = usage.get(key);
    let get = |k: &str| {
        u.and_then(|u| u.get(k))
            .and_then(Value::as_i64)
            .map_or(0, bytes)
    };
    KindTotals {
        count: get("TotalCount"),
        size: get("TotalSize"),
        reclaimable: get("Reclaimable"),
    }
}

fn short_id(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
}

fn is_active_state(state: &str) -> bool {
    matches!(state, "running" | "paused" | "restarting")
}

/// Classifies a `/system/df?verbose=1` response.
pub fn classify_usage(
    usage: &Value,
    allow_volumes: bool,
) -> (Vec<DockerItem>, BTreeMap<ItemKind, KindTotals>) {
    let mut out = Vec::new();

    // Containers, and which images they keep alive.
    // image id -> (running users, stopped users)
    let mut image_users: HashMap<String, (usize, usize)> = HashMap::new();
    for c in items(usage, "ContainerUsage") {
        let id = s(c, "Id").to_string();
        let state = s(c, "State");
        let name = c
            .get("Names")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let image_id = s(c, "ImageID").to_string();
        let active = is_active_state(state);
        let users = image_users.entry(image_id).or_default();
        if active {
            users.0 += 1;
        } else {
            users.1 += 1;
        }
        let (class, reason) = if active {
            (SafetyClass::Protected, format!("container is {state}"))
        } else {
            (
                SafetyClass::Review,
                "stopped container; its writable layer and logs are lost".to_string(),
            )
        };
        out.push(DockerItem {
            kind: ItemKind::Container,
            name: if name.is_empty() {
                short_id(&id).to_string()
            } else {
                name
            },
            detail: format!("{} · {}", s(c, "Image"), s(c, "Status")),
            id,
            size: bytes(n(c, "SizeRw")),
            class,
            reason: Some(reason),
        });
    }

    for i in items(usage, "ImageUsage") {
        let id = s(i, "Id").to_string();
        let tags: Vec<&str> = i
            .get("RepoTags")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|t| *t != "<none>:<none>")
                    .collect()
            })
            .unwrap_or_default();
        let dangling = tags.is_empty();
        let (running, stopped) = image_users.get(&id).copied().unwrap_or((0, 0));
        // Docker's own count also covers containers we did not see.
        let docker_count = n(i, "Containers");
        let (class, reason) = if running > 0 {
            (
                SafetyClass::Protected,
                format!("used by {running} running container(s)"),
            )
        } else if stopped > 0 {
            (
                SafetyClass::Review,
                format!(
                    "used by {stopped} stopped container(s); removed only if they are removed first"
                ),
            )
        } else if docker_count > 0 {
            (
                SafetyClass::Protected,
                format!("used by {docker_count} container(s)"),
            )
        } else if dangling {
            (SafetyClass::Safe, "dangling image (no tag)".to_string())
        } else {
            (
                SafetyClass::Review,
                "unused tagged image; must be pulled or rebuilt again".to_string(),
            )
        };
        let size = n(i, "Size");
        let shared = n(i, "SharedSize");
        let unique = if shared >= 0 { size - shared } else { size };
        out.push(DockerItem {
            kind: ItemKind::Image,
            name: if dangling {
                "<none>".into()
            } else {
                tags.join(", ")
            },
            detail: short_id(&id).to_string(),
            id,
            size: bytes(unique),
            class,
            reason: Some(reason),
        });
    }

    for v in items(usage, "VolumeUsage") {
        let name = s(v, "Name").to_string();
        let usage_data = v.get("UsageData");
        let refs = usage_data.map_or(-1, |u| n(u, "RefCount"));
        let size = usage_data.map_or(0, |u| bytes(n(u, "Size")));
        let (class, reason) = if refs != 0 {
            (
                SafetyClass::Protected,
                if refs > 0 {
                    format!("in use by {refs} container(s)")
                } else {
                    "usage unknown".to_string()
                },
            )
        } else if allow_volumes {
            (
                SafetyClass::Review,
                "unused volume; may contain databases or other data that cannot be recovered"
                    .to_string(),
            )
        } else {
            (
                SafetyClass::Protected,
                "volumes may hold databases; enable volume cleanup to select".to_string(),
            )
        };
        out.push(DockerItem {
            kind: ItemKind::Volume,
            detail: s(v, "Driver").to_string(),
            id: name.clone(),
            name,
            size,
            class,
            reason: Some(reason),
        });
    }

    let build_items = items(usage, "BuildCacheUsage");
    let unused: Vec<&Value> = build_items
        .iter()
        .filter(|b| !b.get("InUse").and_then(Value::as_bool).unwrap_or(true))
        .collect();
    let build_totals = totals(usage, "BuildCacheUsage");
    // Prefer Docker's estimate (accounts for shared records).
    let unused_size = if build_totals.reclaimable > 0 {
        build_totals.reclaimable
    } else {
        unused.iter().map(|b| bytes(n(b, "Size"))).sum()
    };
    if !unused.is_empty() && unused_size > 0 {
        out.push(DockerItem {
            kind: ItemKind::BuildCache,
            id: "unused".into(),
            name: "Unused build cache".into(),
            detail: format!("{} of {} records", unused.len(), build_items.len()),
            size: unused_size,
            class: SafetyClass::Safe,
            reason: Some("BuildKit removes only records not in use; rebuilt on demand".into()),
        });
    }

    let mut t = BTreeMap::new();
    t.insert(ItemKind::Container, totals(usage, "ContainerUsage"));
    t.insert(ItemKind::Image, totals(usage, "ImageUsage"));
    t.insert(ItemKind::Volume, totals(usage, "VolumeUsage"));
    t.insert(ItemKind::BuildCache, build_totals);

    out.sort_by(|a, b| a.kind.cmp(&b.kind).then(b.size.cmp(&a.size)));
    (out, t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!({
            "ContainerUsage": {"TotalCount": 3, "Items": [
                {"Id": "c-run", "Names": ["/web"], "Image": "nginx", "ImageID": "img-nginx", "State": "running", "Status": "Up", "SizeRw": 10},
                {"Id": "c-stop", "Names": ["/old"], "Image": "redis", "ImageID": "img-redis", "State": "exited", "Status": "Exited (0)", "SizeRw": 20},
                {"Id": "c-pause", "Names": ["/p"], "Image": "x", "ImageID": "img-x", "State": "paused", "Status": "Paused", "SizeRw": 5}
            ]},
            "ImageUsage": {"TotalCount": 5, "Reclaimable": 999, "Items": [
                {"Id": "img-nginx", "RepoTags": ["nginx:latest"], "Size": 100, "SharedSize": 0, "Containers": 1},
                {"Id": "img-redis", "RepoTags": ["redis:7"], "Size": 200, "SharedSize": 50, "Containers": 1},
                {"Id": "img-dangling", "RepoTags": ["<none>:<none>"], "Size": 300, "SharedSize": 0, "Containers": 0},
                {"Id": "img-tagged", "RepoTags": ["node:20"], "Size": 400, "SharedSize": -1, "Containers": 0},
                {"Id": "img-x", "RepoTags": [], "Size": 1, "SharedSize": 0, "Containers": 1}
            ]},
            "VolumeUsage": {"Items": [
                {"Name": "pgdata", "Driver": "local", "UsageData": {"Size": 5000, "RefCount": 1}},
                {"Name": "orphan", "Driver": "local", "UsageData": {"Size": 700, "RefCount": 0}},
                {"Name": "nodata", "Driver": "local"}
            ]},
            "BuildCacheUsage": {"Reclaimable": 800, "TotalCount": 3, "Items": [
                {"ID": "b1", "InUse": false, "Size": 500},
                {"ID": "b2", "InUse": false, "Size": 400},
                {"ID": "b3", "InUse": true, "Size": 100}
            ]}
        })
    }

    fn find<'a>(items: &'a [DockerItem], id: &str) -> &'a DockerItem {
        items
            .iter()
            .find(|i| i.id == id)
            .unwrap_or_else(|| panic!("{id} missing"))
    }

    #[test]
    fn classifies_all_kinds() {
        let (items, totals) = classify_usage(&fixture(), false);
        assert_eq!(find(&items, "c-run").class, SafetyClass::Protected);
        assert_eq!(find(&items, "c-pause").class, SafetyClass::Protected);
        assert_eq!(find(&items, "c-stop").class, SafetyClass::Review);
        assert_eq!(find(&items, "c-stop").name, "old");

        assert_eq!(find(&items, "img-nginx").class, SafetyClass::Protected);
        assert_eq!(find(&items, "img-x").class, SafetyClass::Protected);
        assert_eq!(find(&items, "img-redis").class, SafetyClass::Review);
        assert_eq!(
            find(&items, "img-redis").size,
            150,
            "unique size excludes shared layers"
        );
        assert_eq!(find(&items, "img-dangling").class, SafetyClass::Safe);
        assert_eq!(find(&items, "img-tagged").class, SafetyClass::Review);
        assert_eq!(find(&items, "img-tagged").size, 400);

        assert_eq!(find(&items, "pgdata").class, SafetyClass::Protected);
        assert_eq!(find(&items, "orphan").class, SafetyClass::Protected);
        assert_eq!(find(&items, "nodata").class, SafetyClass::Protected);

        let build = find(&items, "unused");
        assert_eq!(build.class, SafetyClass::Safe);
        assert_eq!(build.size, 800);
        assert_eq!(totals[&ItemKind::Image].reclaimable, 999);
    }

    #[test]
    fn unused_volumes_become_review_only_when_enabled() {
        let (items, _) = classify_usage(&fixture(), true);
        assert_eq!(find(&items, "orphan").class, SafetyClass::Review);
        assert_eq!(find(&items, "pgdata").class, SafetyClass::Protected);
        assert_eq!(find(&items, "nodata").class, SafetyClass::Protected);
    }

    #[test]
    fn empty_response_is_fine() {
        let (items, _) = classify_usage(&json!({}), true);
        assert!(items.is_empty());
    }
}
