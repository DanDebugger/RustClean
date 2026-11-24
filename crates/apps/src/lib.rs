//! Application engine: installed-app detection and leftover finding.

pub mod detector;
pub mod leftovers;

pub use detector::{InstalledApp, installed_apps};
pub use leftovers::{LeftoversModule, vendor_of};
