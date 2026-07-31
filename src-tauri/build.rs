// Tauri build-script.
// Запускает codegen для tauri.conf.json и Windows-resource (иконка/манифест).
fn main() {
    tauri_build::build();
}
