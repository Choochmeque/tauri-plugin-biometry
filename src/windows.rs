use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

use windows::{
    core::*,
    Foundation::IAsyncOperation,
    Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerificationResult, UserConsentVerifierAvailability,
    },
    Security::Credentials::{
        KeyCredentialManager, KeyCredentialCreationOption, KeyCredentialRetrievalResult,
    },
    Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{
            FindWindowW, SetForegroundWindow, ShowWindow, BringWindowToTop,
            IsIconic, SW_RESTORE,
        },
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
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
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
        if hwnd.is_ok() {
            let hwnd = hwnd.unwrap();
            if IsIconic(hwnd).as_bool() {
                ShowWindow(hwnd, SW_RESTORE);
            }
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
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
            .map_err(|e| crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to check availability: {:?}", e))))?
            .get()
            .map_err(|e| crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to get availability: {:?}", e))))?;

        Ok(Status {
            is_available: matches!(
                availability,
                UserConsentVerifierAvailability::Available
            ),
            biometry_type: if matches!(
                availability,
                UserConsentVerifierAvailability::Available
            ) {
                BiometryType::FaceID // Windows Hello supports multiple modalities, but we simplify here
            } else {
                BiometryType::None
            },
            error: None,
            error_code: None,
        })
    }

    pub fn authenticate(&self, _reason: String, _options: AuthOptions) -> crate::Result<()> {
        let result = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
            .map_err(|e| {
                crate::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to request verification: {:?}", e),
                ))
            })?
            .get()
            .map_err(|e| {
                crate::Error::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get verification result: {:?}", e),
                ))
            })?;

        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::DeviceBusy => Err(crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "Device is busy"))),
            UserConsentVerificationResult::DeviceNotPresent => Err(crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "No biometric device found"))),
            UserConsentVerificationResult::DisabledByPolicy => Err(crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "Biometric authentication is disabled by policy"))),
            UserConsentVerificationResult::NotConfiguredForUser => Err(crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "Biometric authentication is not configured for the user"))),
            _ => Err(crate::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "Authentication failed"))),
        }
    }

    pub fn has_data(&self, _options: DataOptions) -> crate::Result<bool> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
    }

    pub fn get_data(&self, _options: GetDataOptions) -> crate::Result<DataResponse> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
    }

    pub fn set_data(&self, _options: SetDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
    }

    pub fn remove_data(&self, _options: RemoveDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
    }
}
