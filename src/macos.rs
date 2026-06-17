use objc2_core_foundation::{
    kCFCopyStringDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFBoolean, CFData,
    CFDictionary, CFIndex, CFRetained, CFString, CFType,
};
use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
use objc2_security::{
    errSecDuplicateItem, errSecInteractionNotAllowed, errSecItemNotFound, errSecSuccess,
    errSecUserCanceled, kSecAttrAccessControl, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitOne, kSecReturnData, kSecUseAuthenticationContext, kSecUseDataProtectionKeychain,
    kSecValueData, SecAccessControl, SecAccessControlCreateFlags, SecItemAdd, SecItemCopyMatching,
    SecItemDelete, SecItemUpdate,
};
use serde::de::DeserializeOwned;
use std::ffi::c_void;
use tauri::{plugin::PluginApi, AppHandle, Runtime, WebviewWindow};

use crate::error::{ErrorResponse, PluginInvokeError};
use crate::models::{
    AuthOptions, BiometryType, DataOptions, DataResponse, GetDataOptions, RemoveDataOptions,
    SetDataOptions, Status,
};

// Signature must match the cross-platform plugin contract — return type is
// fixed even though macOS init can't fail.
#[allow(clippy::unnecessary_wraps)]
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

fn reject(code: &str, message: &str) -> crate::Error {
    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
        code: Some(code.to_string()),
        message: Some(message.to_string()),
        data: (),
    }))
}

fn cf_len(n: usize) -> crate::Result<CFIndex> {
    CFIndex::try_from(n)
        .map_err(|_| reject("internalError", "CF array length does not fit in CFIndex"))
}

const fn la_error_to_string(error: LAError) -> &'static str {
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
    // macOS uses global LAContext/Keychain APIs, so methods don't need
    // per-instance state. Signatures match the cross-platform shape.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub fn status(&self) -> crate::Result<Status> {
        let context = unsafe { LAContext::new() };

        let can_evaluate = unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        };

        let biometry_type = unsafe { context.biometryType() };

        let is_available = can_evaluate.is_ok();
        let (error_reason, error_code) = if let Err(error) = can_evaluate {
            let ns_error = &*error;
            let description = ns_error.localizedDescription();
            let code = LAError(ns_error.code());
            (
                Some(description.to_string()),
                Some(la_error_to_string(code).to_string()),
            )
        } else {
            (None, None)
        };

        // Map LABiometryType to our BiometryType enum
        let mapped_biometry_type = match biometry_type {
            LABiometryType::TouchID => BiometryType::TouchID,
            LABiometryType::FaceID => BiometryType::FaceID,
            _ => BiometryType::None,
        };

        Ok(Status {
            is_available,
            biometry_type: mapped_biometry_type,
            error: error_reason,
            error_code,
        })
    }

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn authenticate(
        &self,
        _window: WebviewWindow<R>,
        reason: String,
        options: AuthOptions,
    ) -> crate::Result<()> {
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

                return Err(reject(error_code, &description.to_string()));
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

            context.evaluatePolicy_localizedReason_reply(
                policy,
                &reason_str,
                &block2::StackBlock::new(
                    move |success: objc2::runtime::Bool,
                          error_ptr: *mut objc2_foundation::NSError| {
                        if success.as_bool() {
                            let _ = tx.send(Ok(()));
                        } else if !error_ptr.is_null() {
                            let error = &*error_ptr;
                            let description = error.localizedDescription().to_string();
                            let code = LAError(error.code());
                            let error_code = la_error_to_string(code);

                            let _ = tx.send(Err(reject(error_code, &description)));
                        } else {
                            let _ = tx.send(Err(reject("authenticationFailed", "Unknown error")));
                        }
                    },
                ),
            );
        }

        // Wait for authentication result
        rx.recv().unwrap_or_else(|_| {
            Err(reject(
                "authenticationFailed",
                "Failed to receive authentication result",
            ))
        })
    }

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn has_data(&self, options: DataOptions) -> crate::Result<bool> {
        unsafe {
            let account_cf: CFRetained<CFString> = CFString::from_str(&options.name);
            let service_cf: CFRetained<CFString> = CFString::from_str(&options.domain);

            // `kSecUseDataProtectionKeychain` opts every SecItem call in
            // this file into the modern data-protection keychain — the
            // only backend on macOS that honors `SecAccessControl`
            // (biometric gating). Without it `secd` falls back to the
            // legacy file keychain, generates an implicit
            // `kSecAttrAccess` from `kSecAttrAccessible`, and rejects
            // writes that also pass `kSecAttrAccessControl` with
            // errSecParam ("conflicting kSecAccess and
            // kSecAccessControl attributes"). The flag must be present
            // on EVERY call (add/copy/update/delete) so they all
            // address the same backend.
            // Replaces the deprecated kSecUseAuthenticationUI=Fail dance:
            // an LAContext with interactionNotAllowed=true makes
            // SecItemCopyMatching return errSecInteractionNotAllowed
            // instead of prompting, which is exactly what has_data needs.
            let auth_ctx = LAContext::new();
            auth_ctx.setInteractionNotAllowed(true);
            let auth_ctx_cf: &CFType = &*std::ptr::addr_of!(*auth_ctx).cast::<CFType>();

            let true_ref = CFBoolean::new(true).as_ref();
            let keys: [&CFType; 6] = [
                kSecClass.as_ref(),
                kSecMatchLimit.as_ref(),
                kSecUseAuthenticationContext.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecUseDataProtectionKeychain.as_ref(),
            ];
            let values: [&CFType; 6] = [
                kSecClassGenericPassword.as_ref(),
                kSecMatchLimitOne.as_ref(),
                auth_ctx_cf,
                account_cf.as_ref(),
                service_cf.as_ref(),
                true_ref,
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr().cast::<*const c_void>().cast_mut(),
                values.as_ptr().cast::<*const c_void>().cast_mut(),
                cf_len(keys.len())?,
                std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            )
            .ok_or_else(|| reject("internalError", "Failed to create CFDictionary for query"))?;

            let status = SecItemCopyMatching(&query, std::ptr::null_mut());

            if status == errSecSuccess || status == errSecInteractionNotAllowed {
                Ok(true)
            } else if status == errSecItemNotFound {
                Ok(false)
            } else {
                Err(reject(
                    "keychainError",
                    &format!("SecItemCopyMatching failed with status: {status}"),
                ))
            }
        }
    }

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn get_data(
        &self,
        _window: WebviewWindow<R>,
        options: GetDataOptions,
    ) -> crate::Result<DataResponse> {
        unsafe {
            let cf_account: CFRetained<CFString> = CFString::from_str(&options.name);
            let cf_service: CFRetained<CFString> = CFString::from_str(&options.domain);

            // Replaces the deprecated kSecUseOperationPrompt: an LAContext
            // with localizedReason set carries the prompt text through
            // kSecUseAuthenticationContext.
            let auth_ctx = LAContext::new();
            let reason_ns = objc2_foundation::NSString::from_str(&options.reason);
            auth_ctx.setLocalizedReason(&reason_ns);
            let auth_ctx_cf: &CFType = &*std::ptr::addr_of!(*auth_ctx).cast::<CFType>();

            let true_ref = CFBoolean::new(true).as_ref();
            let keys: [&CFType; 7] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecReturnData.as_ref(),
                kSecMatchLimit.as_ref(),
                kSecUseAuthenticationContext.as_ref(),
                kSecUseDataProtectionKeychain.as_ref(),
            ];
            let values: [&CFType; 7] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
                true_ref,
                kSecMatchLimitOne.as_ref(),
                auth_ctx_cf,
                true_ref,
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr().cast::<*const c_void>().cast_mut(),
                values.as_ptr().cast::<*const c_void>().cast_mut(),
                cf_len(keys.len())?,
                std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            )
            .ok_or_else(|| reject("internalError", "Failed to create CFDictionary for query"))?;

            let mut out: *const CFType = std::ptr::null();
            let status = SecItemCopyMatching(&query, &mut out);

            if status == errSecSuccess {
                if out.is_null() {
                    Err(reject(
                        "dataError",
                        "SecItemCopyMatching returned null data",
                    ))
                } else {
                    let cf_data: &CFData = &*out.cast::<CFData>();
                    let bytes = cf_data.byte_ptr();
                    let data = std::slice::from_raw_parts(bytes, cf_data.len() as usize);
                    Ok(DataResponse {
                        domain: options.domain,
                        name: options.name,
                        data: String::from_utf8_lossy(data).to_string(),
                    })
                }
            } else if status == errSecItemNotFound {
                Err(reject(
                    "itemNotFound",
                    &format!("Error retrieving item from keychain: {status}"),
                ))
            } else if status == errSecUserCanceled {
                Err(reject("userCancel", "User canceled"))
            } else if status == errSecInteractionNotAllowed {
                Err(reject(
                    "authenticationRequired",
                    "Authentication required but UI interaction is not allowed",
                ))
            } else {
                Err(reject(
                    "keychainError",
                    &format!("Error retrieving item from keychain: {status}"),
                ))
            }
        }
    }

    #[allow(
        clippy::unused_self,
        clippy::needless_pass_by_value,
        clippy::too_many_lines
    )]
    pub fn set_data(
        &self,
        _window: WebviewWindow<R>,
        options: SetDataOptions,
    ) -> crate::Result<()> {
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
            .ok_or_else(|| reject("internalError", "Failed to create SecAccessControl"))?;

            // Attributes for SecItemAdd. The `SecAccessControl` built
            // above already encodes the accessibility class — passing
            // `kSecAttrAccessible` here in addition would conflict
            // (errSecParam, "kSecAccess and kSecAccessControl"). We
            // also opt into the data-protection keychain so
            // `kSecAttrAccessControl` is honored.
            let true_ref = CFBoolean::new(true).as_ref();
            let keys: [&CFType; 6] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecValueData.as_ref(),
                kSecAttrAccessControl.as_ref(),
                kSecUseDataProtectionKeychain.as_ref(),
            ];
            let values: [&CFType; 6] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
                cf_value.as_ref(),
                ac_ref.as_ref(),
                true_ref,
            ];

            let add_dict = CFDictionary::new(
                None,
                keys.as_ptr().cast::<*const c_void>().cast_mut(),
                values.as_ptr().cast::<*const c_void>().cast_mut(),
                cf_len(keys.len())?,
                std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            )
            .ok_or_else(|| {
                reject(
                    "internalError",
                    "Failed to create CFDictionary for add_dict",
                )
            })?;

            let mut status = SecItemAdd(&add_dict, std::ptr::null_mut());
            if status == errSecDuplicateItem {
                // Query dict (class + account + service). Same backend
                // opt-in as the add — otherwise SecItemUpdate looks at
                // the legacy keychain and reports "not found" for an
                // item that lives in the data-protection backend.
                let q_keys: [&CFType; 4] = [
                    kSecClass.as_ref(),
                    kSecAttrAccount.as_ref(),
                    kSecAttrService.as_ref(),
                    kSecUseDataProtectionKeychain.as_ref(),
                ];
                let q_vals: [&CFType; 4] = [
                    kSecClassGenericPassword.as_ref(),
                    cf_account.as_ref(),
                    cf_service.as_ref(),
                    true_ref,
                ];

                let query = CFDictionary::new(
                    None,
                    q_keys.as_ptr().cast::<*const c_void>().cast_mut(),
                    q_vals.as_ptr().cast::<*const c_void>().cast_mut(),
                    cf_len(q_keys.len())?,
                    std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                    std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
                )
                .ok_or_else(|| {
                    reject(
                        "internalError",
                        "Failed to create CFDictionary for update query",
                    )
                })?;

                // Update dict (value data + access control). Same
                // reasoning as the add path: `SecAccessControl` already
                // carries the accessibility class, so passing
                // `kSecAttrAccessible` separately collides with
                // `kSecAttrAccessControl`.
                let u_keys: [&CFType; 2] = [kSecValueData.as_ref(), kSecAttrAccessControl.as_ref()];
                let u_vals: [&CFType; 2] = [cf_value.as_ref(), ac_ref.as_ref()];

                let update_dict = CFDictionary::new(
                    None,
                    u_keys.as_ptr().cast::<*const c_void>().cast_mut(),
                    u_vals.as_ptr().cast::<*const c_void>().cast_mut(),
                    cf_len(u_keys.len())?,
                    std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                    std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
                )
                .ok_or_else(|| {
                    reject(
                        "internalError",
                        "Failed to create CFDictionary for update_dict",
                    )
                })?;

                status = SecItemUpdate(&query, &update_dict);
            }

            if status == errSecSuccess {
                Ok(())
            } else {
                Err(reject(
                    "keychainError",
                    &format!("Error adding item to keychain: {status}"),
                ))
            }
        }
    }

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        unsafe {
            let cf_account: CFRetained<CFString> = CFString::from_str(&options.name);
            let cf_service: CFRetained<CFString> = CFString::from_str(&options.domain);

            // Build immutable CFDictionary with 4 key-value pairs. The
            // `kSecUseDataProtectionKeychain` flag matches the
            // backend the corresponding `set_data` writes into;
            // without it the delete targets the legacy keychain and
            // misses items stored under the modern backend.
            let true_ref = CFBoolean::new(true).as_ref();
            let keys: [&CFType; 4] = [
                kSecClass.as_ref(),
                kSecAttrAccount.as_ref(),
                kSecAttrService.as_ref(),
                kSecUseDataProtectionKeychain.as_ref(),
            ];
            let values: [&CFType; 4] = [
                kSecClassGenericPassword.as_ref(),
                cf_account.as_ref(),
                cf_service.as_ref(),
                true_ref,
            ];

            let query = CFDictionary::new(
                None,
                keys.as_ptr().cast::<*const c_void>().cast_mut(),
                values.as_ptr().cast::<*const c_void>().cast_mut(),
                cf_len(keys.len())?,
                std::ptr::addr_of!(kCFCopyStringDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            )
            .ok_or_else(|| {
                reject(
                    "internalError",
                    "Failed to create CFDictionary for delete query",
                )
            })?;

            let status = SecItemDelete(&query);

            if status == errSecSuccess || status == errSecItemNotFound {
                Ok(())
            } else {
                Err(reject(
                    "keychainError",
                    &format!("Error deleting item from keychain: {status}"),
                ))
            }
        }
    }
}
