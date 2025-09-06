use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

fn la_error_to_string(error: LAError) -> &'static str {
    match error {
        LAError::AppCancel => "appCancel",
        LAError::AuthenticationFailed => "authenticationFailed",
        LAError::InvalidContext => "invalidContext",
        LAError::NotInteractive => "notInteractive",
        LAError::PasscodeNotSet => "passcodeNotSet",
        LAError::SystemCancel => "systemCancel",
        LAError::UserCancel => "userCancel",
        LAError::UserFallback => "userFallback",
        LAError::BiometryLockout => "biometryLockout",
        LAError::BiometryNotAvailable => "biometryNotAvailable",
        LAError::BiometryNotEnrolled => "biometryNotEnrolled",
        _ => "unknown",
    }
}

/// Access to the biometry APIs.
pub struct Biometry<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Biometry<R> {
    pub fn status(&self) -> crate::Result<Status> {
        let context = unsafe { LAContext::new() };

        let can_evaluate = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };

        let biometry_type = unsafe { context.biometryType() };

        let is_available = can_evaluate.is_ok();
        let mut error_reason: Option<String> = None;
        let mut error_code: Option<String> = None;

        if let Err(error) = can_evaluate {
            let ns_error = &*error;

            // Get error description
            let description = ns_error.localizedDescription();
            error_reason = Some(description.to_string());

            // Map error code to string representation
            let code = LAError(ns_error.code());
            error_code = Some(la_error_to_string(code).to_string());
        }

        // Map LABiometryType to our BiometryType enum
        let mapped_biometry_type = match biometry_type {
            LABiometryType::None => BiometryType::None,
            LABiometryType::TouchID => BiometryType::TouchID,
            LABiometryType::FaceID => BiometryType::FaceID,
            #[allow(unreachable_patterns)]
            _ => BiometryType::None,
        };

        Ok(Status {
            is_available,
            biometry_type: mapped_biometry_type,
            error: error_reason,
            error_code,
        })
    }

    pub fn authenticate(&self, reason: String, options: AuthOptions) -> crate::Result<()> {
        let context = unsafe { LAContext::new() };

        // Check if biometry is available or device credential is allowed
        let can_evaluate_biometry = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };

        let allow_device_credential = options.allow_device_credential.unwrap_or(false);

        if can_evaluate_biometry.is_err() && !allow_device_credential {
            // Biometry unavailable and fallback disabled
            if let Err(error) = can_evaluate_biometry {
                let ns_error = &*error;
                let description = ns_error.localizedDescription();
                let code = LAError(ns_error.code());
                let error_code = la_error_to_string(code);

                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{error_code}: {description}"),
                )));
            }
        }

        // Set localized titles if provided
        if let Some(fallback_title) = options.fallback_title {
            unsafe {
                let title_str = objc2_foundation::NSString::from_str(&fallback_title);
                context.setLocalizedFallbackTitle(Some(&title_str));
            }
        }

        if let Some(cancel_title) = options.cancel_title {
            unsafe {
                let title_str = objc2_foundation::NSString::from_str(&cancel_title);
                context.setLocalizedCancelTitle(Some(&title_str));
            }
        }

        // Set authentication reuse duration to 0 (no reuse)
        unsafe {
            context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
        }

        // Determine which policy to use
        let policy = if allow_device_credential {
            LAPolicy::DeviceOwnerAuthentication
        } else {
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics
        };

        // Create a channel to communicate between the callback and the main thread
        let (tx, rx) = std::sync::mpsc::channel();

        // Perform authentication
        unsafe {
            let reason_str = objc2_foundation::NSString::from_str(&reason);
            let tx_clone = tx.clone();

            context.evaluatePolicy_localizedReason_reply(
                policy,
                &reason_str,
                &block2::StackBlock::new(
                    move |success: objc2::runtime::Bool,
                          error_ptr: *mut objc2_foundation::NSError| {
                        if success.as_bool() {
                            let _ = tx_clone.send(Ok(()));
                        } else if !error_ptr.is_null() {
                            let error = &*error_ptr;
                            let description = error.localizedDescription().to_string();
                            let code = LAError(error.code());
                            let error_code = la_error_to_string(code);

                            let _ = tx_clone.send(Err(crate::Error::Io(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("{error_code}: {description}"),
                            ))));
                        } else {
                            let _ = tx_clone.send(Err(crate::Error::Io(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "authenticationFailed: Unknown error".to_string(),
                            ))));
                        }
                    },
                ),
            );
        }

        // Wait for authentication result
        match rx.recv() {
            Ok(result) => result,
            Err(_) => Err(crate::Error::Io(std::io::Error::other(
                "authenticationFailed: Failed to receive authentication result",
            ))),
        }
    }

    pub fn has_data(&self, _options: DataOptions) -> crate::Result<bool> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry has_data is not yet implemented on macOS",
        )))
    }

    pub fn get_data(&self, _options: GetDataOptions) -> crate::Result<DataResponse> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry get_data is not yet implemented on macOS",
        )))
    }

    pub fn set_data(&self, _options: SetDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry set_data is not yet implemented on macOS",
        )))
    }

    pub fn remove_data(&self, _options: RemoveDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry remove_data is not yet implemented on macOS",
        )))
    }
}
