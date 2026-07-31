// Windows-специфичная интеграция.
// Все функции этого модуля компилируются только на Windows.
// На других ОС эти модули не используются, но билд должен оставаться возможным
// для разработки UI на macOS/Linux (моки в commands/system при cfg(not(windows))).

pub mod clipboard;
pub mod cng_hello;
pub mod dpapi;
pub mod hello;
pub mod idle;
pub mod session;
pub mod vbs;

/// Сводный отчёт о возможностях ОС.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemCapabilities {
    pub dpapi_available: bool,
    pub windows_hello_available: bool,
    pub vbs_enclave_available: bool,
    /// True = есть TPM 2.0 + настроена Hello-биометрия/PIN.
    /// False = либо TPM нет, либо у пользователя не настроены credentials.
    pub tpm_available: bool,
    pub windows_version: String,
}

pub fn capabilities() -> SystemCapabilities {
    SystemCapabilities {
        dpapi_available: dpapi::is_available(),
        windows_hello_available: hello::is_available(),
        vbs_enclave_available: vbs::is_supported(),
        tpm_available: cng_hello::is_supported(),
        windows_version: detect_windows_version(),
    }
}

fn detect_windows_version() -> String {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct OSVERSIONINFOEXW {
        dwOSVersionInfoSize: u32,
        dwMajorVersion: u32,
        dwMinorVersion: u32,
        dwBuildNumber: u32,
        dwPlatformId: u32,
        szCSDVersion: [u16; 128],
        wServicePackMajor: u16,
        wServicePackMinor: u16,
        wSuiteMask: u16,
        wProductType: u8,
        wReserved: u8,
    }
    extern "system" {
        fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOEXW) -> i32;
    }
    // SAFETY: We pass a mutable pointer to a zero-initialized OSVERSIONINFOEXW structure of correct size. RtlGetVersion will safely populate it.
    unsafe {
        let mut info: OSVERSIONINFOEXW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        if RtlGetVersion(&mut info) == 0 {
            return format!(
                "{}.{}.{}",
                info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
            );
        }
        "unknown".into()
    }
}
