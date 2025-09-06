use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

use windows::{
    core::*,
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, FindWindowW, IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE,
    },
};

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

#[inline]
fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Try to find and foreground the Windows Hello credential dialog.
fn try_focus_hello_dialog_once() -> bool {
    // Common class name for the PIN/Hello dialog host
    let cls = to_wide("Credential Dialog Xaml Host");
    unsafe {
        let hwnd = FindWindowW(
            windows::core::PCWSTR(cls.as_ptr()),
            windows::core::PCWSTR::null(),
        );
        if let Ok(hwnd) = hwnd {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let _ = BringWindowToTop(hwnd);
            let _ = SetForegroundWindow(hwnd);
            return true;
        }
    }
    false
}

/// Focus the Hello dialog by retrying a few times in a helper thread.
fn nudge_hello_dialog_focus_async(retries: u32, delay_ms: u64) {
    std::thread::spawn(move || {
        // Small initial delay gives the dialog time to appear
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        for _ in 0..retries {
            if try_focus_hello_dialog_once() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    });
}

/// Access to the biometry APIs.
pub struct Biometry<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Biometry<R> {
    pub fn status(&self) -> crate::Result<Status> {
        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|async_op| async_op.get())
            .map_err(|e| {
                crate::Error::from(std::io::Error::other(
                    format!("Failed to check biometry availability: {:?}", e),
                ))
            })?;

        let (is_available, biometry_type, error, error_code) = match availability {
            UserConsentVerifierAvailability::Available => (true, BiometryType::Auto, None, None),
            UserConsentVerifierAvailability::DeviceNotPresent => (
                false,
                BiometryType::None,
                Some("No biometric device found".to_string()),
                Some("biometryNotAvailable".to_string()),
            ),
            UserConsentVerifierAvailability::NotConfiguredForUser => (
                false,
                BiometryType::None,
                Some("Biometric authentication not configured".to_string()),
                Some("biometryNotEnrolled".to_string()),
            ),
            UserConsentVerifierAvailability::DisabledByPolicy => (
                false,
                BiometryType::None,
                Some("Biometric authentication disabled by policy".to_string()),
                Some("biometryNotAvailable".to_string()),
            ),
            UserConsentVerifierAvailability::DeviceBusy => (
                false,
                BiometryType::None,
                Some("Biometric device is busy".to_string()),
                Some("systemCancel".to_string()),
            ),
            _ => (
                false,
                BiometryType::None,
                Some("Unknown availability status".to_string()),
                Some("biometryNotAvailable".to_string()),
            ),
        };

        Ok(Status {
            is_available,
            biometry_type,
            error,
            error_code,
        })
    }

    pub fn authenticate(&self, reason: String, _options: AuthOptions) -> crate::Result<()> {
        let result = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
            .and_then(|async_op| {
                nudge_hello_dialog_focus_async(5, 250);
                async_op.get()
            })
            .map_err(|e| {
                crate::Error::from(std::io::Error::other(
                    format!("Failed to request user verification: {:?}", e),
                ))
            })?;

        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::DeviceBusy => Err(crate::Error::from(
                std::io::Error::new(std::io::ErrorKind::ResourceBusy, "Device is busy"),
            )),
            UserConsentVerificationResult::DeviceNotPresent => Err(crate::Error::from(
                std::io::Error::new(std::io::ErrorKind::NotFound, "No biometric device found"),
            )),
            UserConsentVerificationResult::DisabledByPolicy => {
                Err(crate::Error::from(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Biometric authentication is disabled by policy",
                )))
            }
            UserConsentVerificationResult::NotConfiguredForUser => {
                Err(crate::Error::from(std::io::Error::other(
                    "Biometric authentication is not configured for the user",
                )))
            }
            UserConsentVerificationResult::Canceled => {
                Err(crate::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Authentication was canceled by the user",
                )))
            }
            UserConsentVerificationResult::RetriesExhausted => {
                Err(crate::Error::from(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Too many failed authentication attempts",
                )))
            }
            _ => Err(crate::Error::from(std::io::Error::other(
                "Authentication failed",
            ))),
        }
    }

    pub fn has_data(&self, _options: DataOptions) -> crate::Result<bool> {
        Err(crate::Error::from(std::io::Error::other(
            "Has data is not supported on windows platform",
        )))
    }

    pub fn get_data(&self, _options: GetDataOptions) -> crate::Result<DataResponse> {
        Err(crate::Error::from(std::io::Error::other(
            "Get data is not supported on windows platform",
        )))
    }

    pub fn set_data(&self, _options: SetDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Set data is not supported on windows platform",
        )))
    }

    pub fn remove_data(&self, _options: RemoveDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Remove data is not supported on windows platform",
        )))
    }
}
