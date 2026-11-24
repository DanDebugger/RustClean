//! Browser engines. Only Google Chrome is implemented in v0.1.0; Safari and
//! Firefox are planned.

pub mod chrome;
pub mod module;

pub use chrome::{ChromeClassifier, ChromeInstallation, ChromeProfile, is_chrome_running};
pub use module::ChromeModule;
