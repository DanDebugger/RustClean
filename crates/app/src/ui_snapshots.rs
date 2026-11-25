//! Renders real app screens to PNG at desktop, tablet and phone widths, so
//! the responsive design can be checked visually.
//!
//! Uses a temporary fake home folder: nothing real is scanned for files,
//! and nothing is removed. Docker is shown with fixture data (no engine is
//! contacted).
//!
//!     cargo test -p rustclean -- --ignored ui_snapshots
//!
//! Output: `design/screenshots/<screen>-<width>.png` (git-ignored).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui_kittest::Harness;

use crate::app::RustCleanApp;
use crate::navigation::Page;

/// Desktop, tablet and phone, plus a common Windows laptop: 1366×768 at 125 %
/// scaling leaves about 1093×614 points (saved as `-1093`).
const WIDTHS: [(f32, f32); 4] = [
    (1280.0, 860.0),
    (900.0, 860.0),
    (390.0, 844.0),
    (1093.0, 614.0),
];

fn write(path: &Path, bytes: usize) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![7u8; bytes]).unwrap();
    // Ten days old, so smart recommendations have something to show.
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(10 * 86_400))
        .unwrap();
}

fn fake_home() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = rustclean_safety::platform::canonicalize(tmp.path()).unwrap();
    let mb = 1024 * 1024;
    let c = home.join("Library/Caches");
    write(&c.join("com.mongodb.compass.ShipIt/update.zip"), 9 * mb);
    write(&c.join("us.zoom.updater/installer.pkg"), 5 * mb);
    write(
        &c.join("com.postmanlabs.mac/Cache/Cache_Data/f_000001"),
        3 * mb,
    );
    write(
        &c.join("com.postmanlabs.mac/Cache/Cache_Data/f_000002"),
        2 * mb,
    );
    write(&c.join("JNA/temp/jna123.dylib"), mb);
    write(&home.join("Library/Logs/zoom.us/main.log"), 2 * mb);
    write(
        &home.join("Library/Logs/DiagnosticReports/Chrome-2026-11-02.ips"),
        48 * 1024,
    );
    write(&home.join("Downloads/Setup.dmg"), 8 * mb);
    write(&home.join(".npm/_cacache/content-v2/sha512/aa/bb"), 6 * mb);
    write(&home.join(".m2/repository/org/x/x.jar"), 4 * mb);
    let ud = home.join("Library/Application Support/Google/Chrome/Default");
    write(&ud.join("Bookmarks"), 1024);
    write(&ud.join("GPUCache/data_0"), 2 * mb);
    write(
        &c.join("Google/Chrome/Default/Cache/Cache_Data/f_00a1b2"),
        7 * mb,
    );
    write(&c.join("Google/Chrome/Default/Code Cache/js/abc"), 3 * mb);
    // App Caches: an Electron app and a sandboxed app.
    let support = home.join("Library/Application Support/Slack");
    write(&support.join("Local State"), 512);
    write(&support.join("Cache/Cache_Data/f_000123"), 12 * mb);
    write(&support.join("Code Cache/js/index"), 4 * mb);
    write(&support.join("GPUCache/data_1"), mb);
    write(
        &home.join("Library/Containers/com.example.Notes/Data/Library/Caches/thumbs.db"),
        3 * mb,
    );
    (tmp, home)
}

fn docker_fixture() -> rustclean_containers::DockerReport {
    let usage = serde_json::json!({
        "ContainerUsage": {"TotalCount": 3, "Reclaimable": 17000000, "TotalSize": 17000000, "Items": [
            {"Id": "c1", "Names": ["/web-old"], "Image": "nginx", "ImageID": "img-n", "State": "exited", "Status": "Exited (0) 3 weeks ago", "SizeRw": 9000000}
        ]},
        "ImageUsage": {"TotalCount": 18, "Reclaimable": 9500000000u64, "TotalSize": 14360000000u64, "Items": [
            {"Id": "sha256:070539d814a5", "RepoTags": [], "Size": 3130000000u64, "SharedSize": 0, "Containers": 0},
            {"Id": "sha256:21701d28ffc9", "RepoTags": ["<none>:<none>"], "Size": 3100000000u64, "SharedSize": 0, "Containers": 0},
            {"Id": "sha256:aa", "RepoTags": ["node:20"], "Size": 1100000000u64, "SharedSize": 0, "Containers": 0},
            {"Id": "img-n", "RepoTags": ["nginx:latest"], "Size": 190000000, "SharedSize": 0, "Containers": 1}
        ]},
        "VolumeUsage": {"TotalCount": 60, "Reclaimable": 489000000, "TotalSize": 4370000000u64, "Items": [
            {"Name": "pgdata", "Driver": "local", "UsageData": {"Size": 900000000, "RefCount": 1}}
        ]},
        "BuildCacheUsage": {"TotalCount": 36, "Reclaimable": 488700000, "TotalSize": 2630000000u64, "Items": [
            {"ID": "b1", "InUse": false, "Shared": false, "Size": 488700000}
        ]}
    });
    let (items, totals) = rustclean_containers::classify_usage(&usage, false);
    rustclean_containers::DockerReport {
        endpoint: rustclean_containers::Endpoint {
            name: "OrbStack".into(),
            socket: PathBuf::from("/tmp/fixture.sock"),
        },
        server_version: Some("29.8.2".into()),
        items,
        totals,
    }
}

fn wait_idle(h: &mut Harness<'_, RustCleanApp>) {
    let start = Instant::now();
    loop {
        h.step();
        let busy = h.state().state.as_ref().is_some_and(|s| s.any_busy());
        if !busy || start.elapsed() > Duration::from_secs(60) {
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    for _ in 0..4 {
        h.step();
    }
}

fn shoot(h: &mut Harness<'_, RustCleanApp>, out: &Path, name: &str, width: f32) {
    for _ in 0..3 {
        h.step();
    }
    let img = h.render().expect("render");
    let path = out.join(format!("{name}-{}.png", width as u32));
    img.save(&path).expect("save png");
    println!("wrote {}", path.display());
}

#[test]
#[ignore = "renders PNGs; run explicitly"]
fn ui_snapshots() {
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../design/screenshots");
    fs::create_dir_all(&out).unwrap();
    let (_tmp, home) = fake_home();

    for (w, h) in WIDTHS {
        let home2 = home.clone();
        let mut harness = Harness::builder()
            .with_size([w, h])
            .with_pixels_per_point(2.0)
            .with_theme(egui::Theme::Light)
            .wgpu()
            .build_eframe(move |cc| RustCleanApp::with_home(cc, Some(home2.clone())));

        // Scan the file modules (fake home) and show Docker fixture data.
        {
            let ctx = harness.ctx.clone();
            let app = harness.state_mut();
            let s = app.state.as_mut().unwrap();
            s.junk.start_scan(&ctx);
            s.app_caches.start_scan(&ctx);
            s.browser.start_scan(&ctx);
            s.developer.start_scan(&ctx);
            s.security.start_scan(&ctx);
            s.antivirus.start_check(&ctx);
            s.docker.set_report_for_test(docker_fixture());
        }
        wait_idle(&mut harness);

        harness.state_mut().page = Page::Dashboard;
        shoot(&mut harness, &out, "dashboard", w);

        harness.state_mut().page = Page::JunkCleaner;
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .junk
            .select_for_test(3);
        shoot(&mut harness, &out, "junk", w);
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .junk
            .detail_for_test(true);
        shoot(&mut harness, &out, "junk-detail", w);
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .junk
            .detail_for_test(false);

        harness.state_mut().page = Page::AppCaches;
        {
            let s = harness.state_mut().state.as_mut().unwrap();
            s.app_caches.select_for_test(4);
        }
        shoot(&mut harness, &out, "appcaches", w);
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .app_caches
            .open_confirm();
        shoot(&mut harness, &out, "appcaches-confirm", w);
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .app_caches
            .close_confirm_for_test();
        harness.ctx.set_theme(egui::ThemePreference::Dark);
        shoot(&mut harness, &out, "appcaches-dark", w);
        harness.ctx.set_theme(egui::ThemePreference::Light);

        harness.state_mut().page = Page::SmartScan;
        shoot(&mut harness, &out, "smartscan", w);

        harness.state_mut().page = Page::SecurityCenter;
        shoot(&mut harness, &out, "security", w);

        harness.state_mut().page = Page::Antivirus;
        shoot(&mut harness, &out, "antivirus", w);

        harness.state_mut().page = Page::Docker;
        harness
            .state_mut()
            .state
            .as_mut()
            .unwrap()
            .docker
            .open_confirm_for_test();
        shoot(&mut harness, &out, "docker-confirm", w);
    }
}
