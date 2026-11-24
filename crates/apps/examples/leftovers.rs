//! Read-only: lists app-leftover candidates on this Mac.
//!
//!     cargo run -p rustclean-apps --example leftovers
use rustclean_core::CleanupModule;
fn main() {
    let home = rustclean_safety::home_dir().expect("home");
    let m = rustclean_apps::LeftoversModule::new(home.clone());
    println!("{:?}", m.details());
    for t in m.targets() {
        println!(
            "{:<40} {}",
            t.context.unwrap_or_default(),
            t.root.strip_prefix(&home).unwrap().display()
        );
    }
}
