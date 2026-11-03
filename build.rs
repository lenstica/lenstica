fn main() {
    // Only the GUI build is a Tauri app; headless builds skip the bundle context.
    // `LENSTICA_CROSS_CHECK=1 cargo check --target …` skips it too, because it
    // compiles platform resources (the Windows icon needs a Windows resource
    // compiler); real builds for each platform run on that platform (see CI).
    println!("cargo:rerun-if-env-changed=LENSTICA_CROSS_CHECK");
    if std::env::var_os("LENSTICA_CROSS_CHECK").is_some() {
        // What tauri_build would have told `generate_context!` about the target.
        if let Ok(target) = std::env::var("TARGET") {
            println!("cargo:rustc-env=TAURI_ENV_TARGET_TRIPLE={target}");
        }
    } else {
        #[cfg(feature = "tray")]
        tauri_build::build();
    }
}
