//! Read-only: scans Docker disk usage and dry-runs removal of Safe items.
//!
//!     cargo run -p rustclean-containers --example docker_dry_run

use rustclean_containers::{DockerPlan, ItemKind, discover_endpoints, execute, scan};
use rustclean_core::{Progress, SafetyClass, format_bytes};

fn main() {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let endpoints = discover_endpoints(&home);
    println!(
        "endpoints: {:?}",
        endpoints.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    let Some(ep) = endpoints.first() else { return };
    let report = match scan(ep, false) {
        Ok(r) => r,
        Err(e) => {
            println!("scan failed: {e}");
            return;
        }
    };
    println!("{} (server {:?})", ep.name, report.server_version);
    for kind in [
        ItemKind::Container,
        ItemKind::Image,
        ItemKind::Volume,
        ItemKind::BuildCache,
    ] {
        let items: Vec<_> = report.items.iter().filter(|i| i.kind == kind).collect();
        let by = |c: SafetyClass| items.iter().filter(|i| i.class == c).count();
        let t = &report.totals[&kind];
        println!(
            "  {:<12} items {:>3}  safe {:>3} review {:>3} protected {:>3}  docker-reclaimable {}",
            kind.label(),
            items.len(),
            by(SafetyClass::Safe),
            by(SafetyClass::Review),
            by(SafetyClass::Protected),
            format_bytes(t.reclaimable)
        );
    }
    println!(
        "selectable (Safe+Review): {}",
        format_bytes(report.reclaimable())
    );
    let safe = report.items.iter().filter(|i| i.class == SafetyClass::Safe);
    let plan = DockerPlan::from_selection(safe, true)
        .approve(false, false)
        .expect("approve dry run");
    let r = execute(ep, &plan, &Progress::new(), None).expect("execute");
    for res in &r.results {
        println!(
            "  dry-run {:?} {} {} → {:?}",
            res.item.kind,
            res.item.name,
            format_bytes(res.item.size),
            res.outcome
        );
    }
}
