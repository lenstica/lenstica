/// Embed every language file (`i18n/<code>.json`) for `src/i18n.rs`, so adding
/// a language is adding a file.
fn languages() {
    let dir = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("i18n");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let list: String = files
        .iter()
        .map(|p| {
            let code = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            format!(
                "    ({code:?}, include_str!({:?})),\n",
                p.display().to_string()
            )
        })
        .collect();
    let out =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("set by cargo")).join("languages.rs");
    std::fs::write(out, format!("/// Every language file: its code and its JSON.\npub static CATALOGS: &[(&str, &str)] = &[\n{list}];\n"))
        .expect("cannot write languages.rs");
}

fn main() {
    languages();
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
