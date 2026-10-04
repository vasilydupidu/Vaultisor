// Tauri build-script.
// Запускает codegen для tauri.conf.json и Windows-ресурсы (иконка).
//
// Манифест приложения (зависимость от Common Controls v6) встраивается
// линкером, а не ресурсом tauri-build: ресурс попадает только в основной exe,
// и тестовые бинарники без него не загружались — `TaskDialogIndirect` есть
// лишь в comctl32 v6 (STATUS_ENTRYPOINT_NOT_FOUND). Линкер встраивает один и
// тот же манифест во все бинарники, включая тесты.
fn main() {
    let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("tauri build script failed");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        let manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
}
