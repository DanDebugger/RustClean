//! Chrome as a [`CleanupModule`].

use std::path::PathBuf;

use rustclean_core::{CleanupModule, ScanSpec};

use crate::chrome::{ChromeInstallation, is_chrome_running};

pub struct ChromeModule {
    home: PathBuf,
    installation: Option<ChromeInstallation>,
}

impl ChromeModule {
    pub fn new(home: PathBuf) -> Self {
        let installation = ChromeInstallation::detect(&home);
        Self { home, installation }
    }
}

impl CleanupModule for ChromeModule {
    fn title(&self) -> &str {
        "Browser Cleaner — Google Chrome"
    }

    fn refresh(&mut self) {
        self.installation = ChromeInstallation::detect(&self.home);
    }

    fn is_available(&self) -> bool {
        self.installation.is_some()
    }

    fn details(&self) -> Vec<(String, String)> {
        let Some(chrome) = &self.installation else {
            return vec![(
                "Chrome".into(),
                "Google Chrome was not found, and no Chrome data exists".into(),
            )];
        };
        let app = chrome.app_bundle.as_ref().map_or_else(
            || "Not found (data from a previous installation exists)".to_string(),
            |p| p.display().to_string(),
        );
        let profiles: Vec<String> = chrome.profiles.iter().map(|p| p.label()).collect();
        vec![
            ("Application".into(), app),
            (
                "Profiles".into(),
                if profiles.is_empty() {
                    "None found".into()
                } else {
                    profiles.join(", ")
                },
            ),
        ]
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Bookmarks, passwords, history, cookies, extensions and profiles are never touched."
                .into(),
        ]
    }

    fn prepare_scan(&self) -> ScanSpec {
        match &self.installation {
            Some(chrome) => {
                ScanSpec::new(chrome.scan_targets(), Some(Box::new(chrome.classifier())))
            }
            None => ScanSpec::new(Vec::new(), None),
        }
    }

    fn active_warning(&self) -> Option<String> {
        is_chrome_running().then(|| {
            "Google Chrome is running. Removing cache files while Chrome is open may make it \
             rebuild them or lose cached data it is using. Quit Chrome for best results."
                .to_string()
        })
    }
}
