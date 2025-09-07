use objc2_core_foundation::{
    kCFBooleanTrue, kCFCopyStringDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFData,
    CFDictionary, CFDictionaryKeyCallBacks, CFDictionaryValueCallBacks, CFIndex, CFRetained,
    CFString, CFType,
};
use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
use objc2_security::{
    errSecDuplicateItem, errSecInteractionNotAllowed, errSecItemNotFound, errSecSuccess,
    errSecUserCanceled, kSecAttrAccessControl, kSecAttrAccessible,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitOne, kSecReturnData,
    kSecUseAuthenticationUI, kSecUseAuthenticationUIFail, kSecUseOperationPrompt, kSecValueData,
    SecAccessControl, SecAccessControlCreateFlags, SecItemAdd, SecItemCopyMatching, SecItemDelete,
    SecItemUpdate,
};
use serde::de::DeserializeOwned;
use std::ffi::c_void;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::error::{ErrorResponse, PluginInvokeError};
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

                return Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some(error_code.to_string()),
                        message: Some(description.to_string()),
                        data: (),
                    }),
                ));
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

                            let _ = tx_clone.send(Err(crate::Error::PluginInvoke(
                                PluginInvokeError::InvokeRejected(ErrorResponse {
                                    code: Some(error_code.to_string()),
                                    message: Some(description),
                                    data: (),
                                }),
                            )));
                        } else {
                            let _ = tx_clone.send(Err(crate::Error::PluginInvoke(
                                PluginInvokeError::InvokeRejected(ErrorResponse {
                                    code: Some("authenticationFailed".to_string()),
                                    message: Some("Unknown error".to_string()),
                                    data: (),
                                }),
                            )));
                        }
                    },
                ),
            );
        }

        // Wait for authentication result
        match rx.recv() {
            Ok(result) => result,
            Err(_) => Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("authenticationFailed".to_string()),
                    message: Some("Failed to receive authentication result".to_string()),
                    data: (),
                }),
            )),
        }
    }

    pub fn has_data(&self, options: DataOptions) -> crate::Result<bool> {
        unsafe {
            let account_cf: CFRetained<CFString> = CFString::from_str(&options.name);
            let service_cf: CFRetained<CFString> = CFString::from_str(&options.domain);

            let keys: [&CFType; 5] = [
                kSecClass.as_ref(),
                kSecMatchLimit.as_ref(),
                kSecUseAuthenticationUI.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
            ];
            let values: [&CFType; 5] = [
                kSecClassGenericPassword.as_ref(),
                kSecMatchLimitOne.as_ref(),
                kSecUseAuthenticationUIFail.as_ref(),
                account_cf.as_ref(),
                service_cf.as_ref(),
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr() as *mut *const c_void,
                values.as_ptr() as *mut *const c_void,
                keys.len() as CFIndex,
                &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
            )
            .ok_or_else(|| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some("Failed to create CFDictionary for query".to_string()),
                    data: (),
                }))
            })?;

            let status = SecItemCopyMatching(&query, std::ptr::null_mut());

            if status == errSecSuccess || status == errSecInteractionNotAllowed {
                Ok(true)
            } else if status == errSecItemNotFound {
                Ok(false)
            } else {
                Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("keychainError".to_string()),
                        message: Some(format!("SecItemCopyMatching failed with status: {status}")),
                        data: (),
                    }),
                ))
            }
        }
    }

    pub fn get_data(&self, options: GetDataOptions) -> crate::Result<DataResponse> {
        unsafe {
            let cf_account: CFRetained<CFString> = CFString::from_str(&options.name);
            let cf_service: CFRetained<CFString> = CFString::from_str(&options.domain);
            let cf_reason: CFRetained<CFString> = CFString::from_str(&options.reason);

            let keys: [&CFType; 6] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecReturnData.as_ref(),
                kSecMatchLimit.as_ref(),
                kSecUseOperationPrompt.as_ref(),
            ];
            let values: [&CFType; 6] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
                kCFBooleanTrue.as_ref().ok_or_else(|| {
                    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("internalError".to_string()),
                        message: Some("Failed to get kCFBooleanTrue reference".to_string()),
                        data: (),
                    }))
                })?,
                kSecMatchLimitOne.as_ref(),
                cf_reason.as_ref(),
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr() as *mut *const c_void,
                values.as_ptr() as *mut *const c_void,
                keys.len() as CFIndex,
                &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
            )
            .ok_or_else(|| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some("Failed to create CFDictionary for query".to_string()),
                    data: (),
                }))
            })?;

            let mut out: *const CFType = std::ptr::null();
            let status = SecItemCopyMatching(&query, &mut out);

            if status == errSecSuccess {
                if !out.is_null() {
                    let cf_data: &CFData = &*(out as *const CFData);
                    let bytes = cf_data.byte_ptr();
                    let data = std::slice::from_raw_parts(bytes, cf_data.len() as usize);
                    Ok(DataResponse {
                        domain: options.domain,
                        name: options.name,
                        data: String::from_utf8_lossy(data).to_string(),
                    })
                } else {
                    Err(crate::Error::PluginInvoke(
                        PluginInvokeError::InvokeRejected(ErrorResponse {
                            code: Some("dataError".to_string()),
                            message: Some("SecItemCopyMatching returned null data".to_string()),
                            data: (),
                        }),
                    ))
                }
            } else if status == errSecItemNotFound {
                return Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("itemNotFound".to_string()),
                        message: Some(format!("Error retrieving item from keychain: {status}")),
                        data: (),
                    }),
                ));
            } else if status == errSecUserCanceled {
                return Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("userCancel".to_string()),
                        message: Some("User canceled".to_string()),
                        data: (),
                    }),
                ));
            } else if status == errSecInteractionNotAllowed {
                return Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("authenticationRequired".to_string()),
                        message: Some(
                            "Authentication required but UI interaction is not allowed".to_string(),
                        ),
                        data: (),
                    }),
                ));
            } else {
                return Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("keychainError".to_string()),
                        message: Some(format!("Error retrieving item from keychain: {status}")),
                        data: (),
                    }),
                ));
            }
        }
    }

    pub fn set_data(&self, options: SetDataOptions) -> crate::Result<()> {
        unsafe {
            let cf_account: CFRetained<CFString> = CFString::from_str(&options.name);
            let cf_service: CFRetained<CFString> = CFString::from_str(&options.domain);
            let cf_value: CFRetained<CFData> = CFData::from_bytes(options.data.as_bytes());

            // Create SecAccessControl(userPresence)
            let ac_ref = SecAccessControl::with_flags(
                None,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                SecAccessControlCreateFlags::UserPresence,
                std::ptr::null_mut(),
            )
            .ok_or_else(|| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some("Failed to create SecAccessControl".to_string()),
                    data: (),
                }))
            })?;

            // Attributes for SecItemAdd
            let keys: [&CFType; 6] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecValueData.as_ref(),
                kSecAttrAccessControl.as_ref(),
                kSecAttrAccessible.as_ref(),
            ];
            let values: [&CFType; 6] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
                cf_value.as_ref(),
                ac_ref.as_ref(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly.as_ref(),
            ];

            let add_dict = CFDictionary::new(
                None,
                keys.as_ptr() as *mut *const c_void,
                values.as_ptr() as *mut *const c_void,
                keys.len() as CFIndex,
                &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
            )
            .ok_or_else(|| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some("Failed to create CFDictionary for add_dict".to_string()),
                    data: (),
                }))
            })?;

            let mut status = SecItemAdd(&add_dict, std::ptr::null_mut());
            if status == errSecDuplicateItem {
                // Query dict (class + account + service)
                let q_keys: [&CFType; 3] = [
                    kSecClass.as_ref(),
                    kSecAttrAccount.as_ref(),
                    kSecAttrService.as_ref(),
                ];
                let q_vals: [&CFType; 3] = [
                    kSecClassGenericPassword.as_ref(),
                    cf_account.as_ref(),
                    cf_service.as_ref(),
                ];

                let query = CFDictionary::new(
                    None,
                    q_keys.as_ptr() as *mut *const c_void,
                    q_vals.as_ptr() as *mut *const c_void,
                    q_keys.len() as CFIndex,
                    &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
                )
                .ok_or_else(|| {
                    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("internalError".to_string()),
                        message: Some("Failed to create CFDictionary for update query".to_string()),
                        data: (),
                    }))
                })?;

                // Update dict (value data + access control + accessibility)
                let u_keys: [&CFType; 3] = [
                    kSecValueData.as_ref(),
                    kSecAttrAccessControl.as_ref(),
                    kSecAttrAccessible.as_ref(),
                ];
                let u_vals: [&CFType; 3] = [
                    cf_value.as_ref(),
                    ac_ref.as_ref(),
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly.as_ref(),
                ];

                let update_dict = CFDictionary::new(
                    None,
                    u_keys.as_ptr() as *mut *const c_void,
                    u_vals.as_ptr() as *mut *const c_void,
                    u_keys.len() as CFIndex,
                    &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
                )
                .ok_or_else(|| {
                    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("internalError".to_string()),
                        message: Some("Failed to create CFDictionary for update_dict".to_string()),
                        data: (),
                    }))
                })?;

                status = SecItemUpdate(&query, &update_dict);
            }

            if status == errSecSuccess {
                Ok(())
            } else {
                Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("keychainError".to_string()),
                        message: Some(format!("Error adding item to keychain: {status}")),
                        data: (),
                    }),
                ))
            }
        }
    }

    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        unsafe {
            let cf_account: CFRetained<CFString> = CFString::from_str(&options.name);
            let cf_service: CFRetained<CFString> = CFString::from_str(&options.domain);

            // Build immutable CFDictionary with 3 key-value pairs
            let keys: [&CFType; 3] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
            ];
            let values: [&CFType; 3] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr() as *mut *const c_void,
                values.as_ptr() as *mut *const c_void,
                keys.len() as CFIndex,
                &kCFCopyStringDictionaryKeyCallBacks as *const CFDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks as *const CFDictionaryValueCallBacks,
            )
            .ok_or_else(|| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("internalError".to_string()),
                    message: Some("Failed to create CFDictionary for delete query".to_string()),
                    data: (),
                }))
            })?;

            let status = SecItemDelete(&query);

            if status == errSecSuccess || status == errSecItemNotFound {
                Ok(())
            } else {
                Err(crate::Error::PluginInvoke(
                    PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("keychainError".to_string()),
                        message: Some(format!("Error deleting item from keychain: {status}")),
                        data: (),
                    }),
                ))
            }
        }
    }
}
