// Vaultisor — entry point.
//
// Этот файл — тонкая обёртка. Вся бизнес-логика и регистрация Tauri-команд
// находятся в lib.rs (vaultisor_lib::run).
//
// Атрибут #![cfg_attr(...)] скрывает консольное окно при release-сборке на Windows.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    vaultisor_lib::run();
}
