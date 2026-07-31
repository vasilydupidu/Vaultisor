// VBS (Virtualization-Based Security) Enclave — детектор.
//
// IsEnclaveTypeSupported лежит в kernel32.dll, но его экспорт в windows-rs
// плавает между версиями (в 0.58 он не виден в Win32::System::Threading).
// Чтобы держать сборку версионно-устойчивой, объявляем FFI вручную через
// extern "system" — это и есть тот же символ, который windows-rs обернул бы.
//
// Полноценная работа с VBS Enclave требует подписанного DLL с кодом enclave.
// Здесь — только детектор; это honest MVP, без имитаций.

const ENCLAVE_TYPE_VBS: u32 = 0x00000010;

extern "system" {
    fn IsEnclaveTypeSupported(fl_enclave_type: u32) -> i32;
}

/// Проверить, поддерживает ли система VBS Enclave.
pub fn is_supported() -> bool {
    // SAFETY: The FFI call takes a single integer and returns an integer, with no pointer parameters or allocations. It is fundamentally safe to call.
    unsafe { IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) != 0 }
}

/// Текстовое объяснение для UI: почему недоступно и что делать.
pub fn diagnosis() -> &'static str {
    if is_supported() {
        "VBS Enclave доступен в этой системе."
    } else {
        // Возможные причины: Windows < 11 24H2, отключена виртуализация в BIOS,
        // не Pro/Enterprise SKU, отключена Memory Integrity.
        "VBS Enclave недоступен. Нужны: Windows 11 24H2+, виртуализация в BIOS, \
         Memory Integrity (Core Isolation) включена в настройках Windows Security."
    }
}
