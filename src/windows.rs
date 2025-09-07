use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::error::{ErrorResponse, PluginInvokeError};
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
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some(format!("Failed to check biometry availability: {:?}", e)),
                    data: (),
                }))
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
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some(format!("Failed to request user verification: {:?}", e)),
                    data: (),
                }))
            })?;

        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::DeviceBusy => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("systemCancel".to_string()),
                    message: Some("Device is busy".to_string()),
                    data: (),
                }),
            )),
            UserConsentVerificationResult::DeviceNotPresent => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("biometryNotAvailable".to_string()),
                    message: Some("No biometric device found".to_string()),
                    data: (),
                }),
            )),
            UserConsentVerificationResult::DisabledByPolicy => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("biometryNotAvailable".to_string()),
                    message: Some("Biometric authentication is disabled by policy".to_string()),
                    data: (),
                }),
            )),
            UserConsentVerificationResult::NotConfiguredForUser => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("biometryNotEnrolled".to_string()),
                    message: Some(
                        "Biometric authentication is not configured for the user".to_string(),
                    ),
                    data: (),
                }),
            )),
            UserConsentVerificationResult::Canceled => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("userCancel".to_string()),
                    message: Some("Authentication was canceled by the user".to_string()),
                    data: (),
                }),
            )),
            UserConsentVerificationResult::RetriesExhausted => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("biometryLockout".to_string()),
                    message: Some("Too many failed authentication attempts".to_string()),
                    data: (),
                }),
            )),
            _ => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("authenticationFailed".to_string()),
                    message: Some("Authentication failed".to_string()),
                    data: (),
                }),
            )),
        }
    }

    pub fn has_data(&self, _options: DataOptions) -> crate::Result<bool> {
        Err(crate::Error::PluginInvoke(
            PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("notSupported".to_string()),
                message: Some("Biometry has_data is not supported on Windows platform".to_string()),
                data: (),
            }),
        ))
    }

    pub fn get_data(&self, _options: GetDataOptions) -> crate::Result<DataResponse> {
        Err(crate::Error::PluginInvoke(
            PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("notSupported".to_string()),
                message: Some("Biometry get_data is not supported on Windows platform".to_string()),
                data: (),
            }),
        ))
    }

    pub fn set_data(&self, _options: SetDataOptions) -> crate::Result<()> {
        Err(crate::Error::PluginInvoke(
            PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("notSupported".to_string()),
                message: Some("Biometry set_data is not supported on Windows platform".to_string()),
                data: (),
            }),
        ))
    }

    pub fn remove_data(&self, _options: RemoveDataOptions) -> crate::Result<()> {
        Err(crate::Error::PluginInvoke(
            PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("notSupported".to_string()),
                message: Some(
                    "Biometry remove_data is not supported on Windows platform".to_string(),
                ),
                data: (),
            }),
        ))
    }
}
