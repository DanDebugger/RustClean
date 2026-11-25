//! Embeds the app icon into the Windows executable (Explorer, taskbar,
//! shortcuts). Other targets: nothing to do. The window icon at run time is
//! set separately in main.rs.

fn main() {
    println!("cargo:rerun-if-changed=rustclean.rc");
    println!("cargo:rerun-if-changed=../../assets/RustClean.ico");
    // The *target* OS, not the host: release.sh cross-builds from macOS.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Fail the build rather than ship an .exe without its icon.
        embed_resource::compile("rustclean.rc", embed_resource::NONE)
            .manifest_required()
            .expect("could not embed the Windows icon (windres / rc.exe needed)");
    }
}
