//! Docker cleanup through the Docker Engine API.
//!
//! Docker data lives inside a virtual-machine disk image (Docker Desktop's
//! `Docker.raw`, OrbStack's data image). RustClean never touches those
//! files; everything goes through the engine API, which keeps Docker's own
//! consistency guarantees.
//!
//! Like the file engines, this crate separates a read-only scan
//! ([`scan`]) from execution of an explicitly approved plan
//! ([`DockerPlan::approve`] → [`execute`]). Docker removals are **not
//! reversible**, so approval always requires an irreversibility
//! acknowledgement. Every removal is issued with `force = false`, so the
//! daemon itself refuses to remove running containers, images still used by
//! a container and volumes in use.

pub mod classify;
pub mod endpoint;

pub use classify::{DockerItem, ItemKind, classify_usage};
pub use endpoint::{Endpoint, discover_endpoints};

use std::collections::BTreeMap;
use std::time::Duration;

use bollard::Docker;
use bollard::models::ContainerStateStatusEnum;
use bollard::query_parameters::{
    DataUsageOptions, PruneBuildOptions, RemoveContainerOptions, RemoveImageOptionsBuilder,
    RemoveVolumeOptionsBuilder,
};
use rustclean_core::{OperationLog, Progress, SafetyClass};
use thiserror::Error;

/// Disk-usage computation can be slow on large installations.
const API_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Error)]
pub enum DockerError {
    #[error("could not start async runtime: {0}")]
    Runtime(String),
    #[error("Docker engine at {0} is not reachable: {1}")]
    Unreachable(String, String),
    #[error("Docker API error: {0}")]
    Api(String),
}

fn runtime() -> Result<tokio::runtime::Runtime, DockerError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DockerError::Runtime(e.to_string()))
}

async fn connect(endpoint: &Endpoint) -> Result<Docker, DockerError> {
    let socket = endpoint.socket.to_string_lossy().into_owned();
    let unreachable =
        |e: bollard::errors::Error| DockerError::Unreachable(socket.clone(), e.to_string());
    #[cfg(unix)]
    let docker = Docker::connect_with_unix(&socket, API_TIMEOUT_SECS, bollard::API_DEFAULT_VERSION);
    #[cfg(windows)]
    let docker =
        Docker::connect_with_named_pipe(&socket, API_TIMEOUT_SECS, bollard::API_DEFAULT_VERSION);
    let docker = docker
        .map_err(unreachable)?
        .negotiate_version()
        .await
        .map_err(unreachable)?;
    tokio::time::timeout(Duration::from_secs(10), docker.ping())
        .await
        .map_err(|_| DockerError::Unreachable(socket.clone(), "ping timed out".into()))?
        .map_err(unreachable)?;
    Ok(docker)
}

#[derive(Debug, Clone, Default)]
pub struct KindTotals {
    pub count: u64,
    pub size: u64,
    /// Docker's own reclaimable estimate.
    pub reclaimable: u64,
}

#[derive(Debug, Clone)]
pub struct DockerReport {
    pub endpoint: Endpoint,
    pub server_version: Option<String>,
    pub items: Vec<DockerItem>,
    pub totals: BTreeMap<ItemKind, KindTotals>,
}

impl DockerReport {
    /// Bytes of items the user may select.
    pub fn reclaimable(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.class.is_selectable())
            .map(|i| i.size)
            .sum()
    }
}

/// Read-only: queries disk usage and classifies every item.
pub fn scan(endpoint: &Endpoint, allow_volumes: bool) -> Result<DockerReport, DockerError> {
    runtime()?.block_on(async {
        let docker = connect(endpoint).await?;
        let server_version = docker.version().await.ok().and_then(|v| v.version);
        let usage = docker
            .df(Some(DataUsageOptions {
                verbose: true,
                ..Default::default()
            }))
            .await
            .map_err(|e| DockerError::Api(e.to_string()))?;
        let usage = serde_json::to_value(&usage).map_err(|e| DockerError::Api(e.to_string()))?;
        let (items, totals) = classify_usage(&usage, allow_volumes);
        Ok(DockerReport {
            endpoint: endpoint.clone(),
            server_version,
            items,
            totals,
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerOutcome {
    Removed { reclaimed: Option<u64> },
    WouldRemove,
    Skipped(String),
    Failed(String),
    NotAttempted,
}

#[derive(Debug, Clone)]
pub struct DockerResult {
    pub item: DockerItem,
    pub outcome: DockerOutcome,
}

#[derive(Debug, Clone)]
pub struct DockerCleanupReport {
    pub dry_run: bool,
    pub results: Vec<DockerResult>,
}

impl DockerCleanupReport {
    pub fn count(&self, f: impl Fn(&DockerOutcome) -> bool) -> usize {
        self.results.iter().filter(|r| f(&r.outcome)).count()
    }
    pub fn bytes_affected(&self) -> u64 {
        self.results
            .iter()
            .map(|r| match &r.outcome {
                DockerOutcome::Removed { reclaimed } => reclaimed.unwrap_or(r.item.size),
                DockerOutcome::WouldRemove => r.item.size,
                _ => 0,
            })
            .sum()
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DockerPlanError {
    #[error("nothing selected")]
    Empty,
    #[error("Docker removals cannot be undone; acknowledge this to continue")]
    IrreversibleNotAcknowledged,
    #[error("{0} selected item(s) need review; confirm them explicitly")]
    ReviewNotAcknowledged(usize),
}

#[derive(Debug, Clone)]
pub struct DockerPlan {
    items: Vec<DockerItem>,
    rejected: usize,
    pub dry_run: bool,
}

impl DockerPlan {
    /// Non-selectable items are dropped. Items are ordered so containers
    /// are removed before the images and volumes they reference.
    pub fn from_selection<'a>(
        selected: impl IntoIterator<Item = &'a DockerItem>,
        dry_run: bool,
    ) -> Self {
        let mut items = Vec::new();
        let mut rejected = 0;
        for i in selected {
            if i.class.is_selectable() {
                items.push(i.clone());
            } else {
                rejected += 1;
            }
        }
        items.sort_by_key(|i| i.kind);
        Self {
            items,
            rejected,
            dry_run,
        }
    }

    pub fn items(&self) -> &[DockerItem] {
        &self.items
    }
    pub fn rejected(&self) -> usize {
        self.rejected
    }
    pub fn review_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.class == SafetyClass::Review)
            .count()
    }
    pub fn total_size(&self) -> u64 {
        self.items.iter().map(|i| i.size).sum()
    }

    /// A dry run needs no irreversibility acknowledgement; a real run does.
    pub fn approve(
        self,
        review_acknowledged: bool,
        irreversible_acknowledged: bool,
    ) -> Result<ApprovedDockerPlan, DockerPlanError> {
        if self.items.is_empty() {
            return Err(DockerPlanError::Empty);
        }
        let review = self.review_count();
        if review > 0 && !review_acknowledged {
            return Err(DockerPlanError::ReviewNotAcknowledged(review));
        }
        if !self.dry_run && !irreversible_acknowledged {
            return Err(DockerPlanError::IrreversibleNotAcknowledged);
        }
        Ok(ApprovedDockerPlan(self))
    }
}

/// Only constructible via [`DockerPlan::approve`].
#[derive(Debug, Clone)]
pub struct ApprovedDockerPlan(DockerPlan);

impl std::ops::Deref for ApprovedDockerPlan {
    type Target = DockerPlan;
    fn deref(&self) -> &DockerPlan {
        &self.0
    }
}

/// Executes an approved plan. Each item is re-checked against the live
/// engine immediately before removal (and in dry runs).
pub fn execute(
    endpoint: &Endpoint,
    plan: &ApprovedDockerPlan,
    progress: &Progress,
    log: Option<&OperationLog>,
) -> Result<DockerCleanupReport, DockerError> {
    let session = format!("docker-{}", std::process::id());
    runtime()?.block_on(async {
        let docker = connect(endpoint).await?;
        let mut results = Vec::with_capacity(plan.items().len());
        for item in plan.items() {
            let outcome = if progress.is_cancelled() {
                DockerOutcome::NotAttempted
            } else {
                process(&docker, item, plan.dry_run).await
            };
            progress.add(1, item.size);
            if let Some(log) = log {
                let (name, detail) = match &outcome {
                    DockerOutcome::Removed { .. } => ("removed", None),
                    DockerOutcome::WouldRemove => ("would_remove", None),
                    DockerOutcome::Skipped(e) => ("skipped", Some(e.as_str())),
                    DockerOutcome::Failed(e) => ("failed", Some(e.as_str())),
                    DockerOutcome::NotAttempted => ("not_attempted", None),
                };
                let path = format!(
                    "docker://{}/{}/{}",
                    endpoint.name,
                    item.kind.slug(),
                    item.id
                );
                log.record(
                    &session,
                    plan.dry_run,
                    "DockerApi",
                    std::path::Path::new(&path),
                    name,
                    detail,
                    None,
                    item.size,
                );
            }
            results.push(DockerResult {
                item: item.clone(),
                outcome,
            });
        }
        tracing::info!(
            dry_run = plan.dry_run,
            items = results.len(),
            "docker cleanup finished"
        );
        Ok(DockerCleanupReport {
            dry_run: plan.dry_run,
            results,
        })
    })
}

async fn process(docker: &Docker, item: &DockerItem, dry_run: bool) -> DockerOutcome {
    let api_err = |e: bollard::errors::Error| {
        // 404: already gone; 409: in use. Both mean "leave it alone".
        match &e {
            bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            } => DockerOutcome::Skipped("no longer exists".into()),
            bollard::errors::Error::DockerResponseServerError {
                status_code: 409,
                message,
            } => DockerOutcome::Skipped(format!("in use: {message}")),
            _ => DockerOutcome::Failed(e.to_string()),
        }
    };
    match item.kind {
        ItemKind::Container => {
            let info = match docker.inspect_container(&item.id, None).await {
                Ok(i) => i,
                Err(e) => return api_err(e),
            };
            let status = info.state.and_then(|s| s.status);
            if matches!(
                status,
                Some(
                    ContainerStateStatusEnum::RUNNING
                        | ContainerStateStatusEnum::PAUSED
                        | ContainerStateStatusEnum::RESTARTING
                )
            ) {
                return DockerOutcome::Skipped("container is running".into());
            }
            if dry_run {
                return DockerOutcome::WouldRemove;
            }
            // v=false keeps anonymous volumes; force=false refuses running.
            let opts = RemoveContainerOptions {
                v: false,
                force: false,
                link: false,
            };
            match docker.remove_container(&item.id, Some(opts)).await {
                Ok(()) => DockerOutcome::Removed { reclaimed: None },
                Err(e) => api_err(e),
            }
        }
        ItemKind::Image => {
            if let Err(e) = docker.inspect_image(&item.id).await {
                return api_err(e);
            }
            if dry_run {
                return DockerOutcome::WouldRemove;
            }
            let opts = RemoveImageOptionsBuilder::new()
                .force(false)
                .noprune(false)
                .build();
            match docker.remove_image(&item.id, Some(opts), None).await {
                Ok(_) => DockerOutcome::Removed { reclaimed: None },
                Err(e) => api_err(e),
            }
        }
        ItemKind::Volume => {
            if let Err(e) = docker.inspect_volume(&item.id).await {
                return api_err(e);
            }
            if dry_run {
                return DockerOutcome::WouldRemove;
            }
            let opts = RemoveVolumeOptionsBuilder::new().force(false).build();
            match docker.remove_volume(&item.id, Some(opts)).await {
                Ok(()) => DockerOutcome::Removed { reclaimed: None },
                Err(e) => api_err(e),
            }
        }
        ItemKind::BuildCache => {
            if dry_run {
                return DockerOutcome::WouldRemove;
            }
            // BuildKit only prunes records that are not in use.
            match docker.prune_build(None::<PruneBuildOptions>).await {
                Ok(r) => DockerOutcome::Removed {
                    reclaimed: r.space_reclaimed.and_then(|s| u64::try_from(s).ok()),
                },
                Err(e) => api_err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ItemKind, class: SafetyClass) -> DockerItem {
        DockerItem {
            kind,
            id: format!("{kind:?}"),
            name: String::new(),
            detail: String::new(),
            size: 10,
            class,
            reason: None,
        }
    }

    #[test]
    fn plan_orders_containers_first_and_drops_unselectable() {
        let items = [
            item(ItemKind::Volume, SafetyClass::Review),
            item(ItemKind::Image, SafetyClass::Safe),
            item(ItemKind::Container, SafetyClass::Review),
            item(ItemKind::Image, SafetyClass::Protected),
        ];
        let plan = DockerPlan::from_selection(&items, true);
        let kinds: Vec<_> = plan.items().iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            vec![ItemKind::Container, ItemKind::Image, ItemKind::Volume]
        );
        assert_eq!(plan.rejected(), 1);
    }

    #[test]
    fn real_run_requires_irreversible_ack() {
        let items = [item(ItemKind::Image, SafetyClass::Safe)];
        let real = DockerPlan::from_selection(&items, false);
        assert_eq!(
            real.clone().approve(true, false).unwrap_err(),
            DockerPlanError::IrreversibleNotAcknowledged
        );
        assert!(real.approve(true, true).is_ok());
        let dry = DockerPlan::from_selection(&items, true);
        assert!(dry.approve(false, false).is_ok());
    }

    #[test]
    fn review_items_require_ack() {
        let items = [item(ItemKind::Container, SafetyClass::Review)];
        let plan = DockerPlan::from_selection(&items, true);
        assert_eq!(
            plan.approve(false, true).unwrap_err(),
            DockerPlanError::ReviewNotAcknowledged(1)
        );
    }
}
