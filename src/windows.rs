use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::error::{ErrorResponse, PluginInvokeError};
use crate::models::*;

use windows::{
    core::*,
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialRetrievalResult,
        KeyCredentialStatus, PasswordCredential, PasswordVault,
    },
    Security::Cryptography::Core::{
        CryptographicEngine, HashAlgorithmNames, HashAlgorithmProvider, SymmetricAlgorithmNames,
        SymmetricKeyAlgorithmProvider,
    },
    Security::Cryptography::{BinaryStringEncoding, CryptographicBuffer},
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

/// Create or open a Windows Hello credential
fn get_credential(domain: &str, create_if_missing: bool) -> Result<KeyCredentialRetrievalResult> {
    let credential_name = HSTRING::from(domain);

    // Focus the Hello dialog
    nudge_hello_dialog_focus_async(5, 250);

    if create_if_missing {
        KeyCredentialManager::RequestCreateAsync(
            &credential_name,
            KeyCredentialCreationOption::ReplaceExisting,
        )?
        .get()
    } else {
        KeyCredentialManager::OpenAsync(&credential_name)?.get()
    }
}

/// Encrypt data using Windows Hello credential
fn encrypt_data(
    domain: &str,
    data: &[u8],
    credential_result: &KeyCredentialRetrievalResult,
) -> Result<String> {
    let status = credential_result.Status()?;
    if status != KeyCredentialStatus::Success {
        return Err(Error::from(HRESULT(-1)));
    }

    let credential = credential_result.Credential()?;
    let challenge_buffer = CryptographicBuffer::ConvertStringToBinary(
        &HSTRING::from(domain),
        BinaryStringEncoding::Utf8,
    )?;

    // Sign the challenge to get a unique key
    let signature = credential.RequestSignAsync(&challenge_buffer)?.get()?;
    let signature_result = signature.Result()?;

    // Use the signature to derive an encryption key
    let hash_provider = HashAlgorithmProvider::OpenAlgorithm(&HashAlgorithmNames::Sha256()?)?;
    let key_hash = hash_provider.HashData(&signature_result)?;

    // Create AES encryption provider
    let aes_provider =
        SymmetricKeyAlgorithmProvider::OpenAlgorithm(&SymmetricAlgorithmNames::AesCbcPkcs7()?)?;

    // Generate a cryptographically random IV (16 bytes for AES-CBC)
    let iv = CryptographicBuffer::GenerateRandom(16)?;

    // Create symmetric key
    let key = aes_provider.CreateSymmetricKey(&key_hash)?;

    // Encrypt the data
    let data_buffer = CryptographicBuffer::CreateFromByteArray(data)?;
    let encrypted_buffer = CryptographicEngine::Encrypt(&key, &data_buffer, Some(&iv))?;

    // Prepend IV to ciphertext so it can be extracted during decryption
    let mut iv_bytes: windows::core::Array<u8> = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(&iv, &mut iv_bytes)?;
    let mut encrypted_bytes: windows::core::Array<u8> = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(&encrypted_buffer, &mut encrypted_bytes)?;

    let mut combined = Vec::with_capacity(iv_bytes.len() + encrypted_bytes.len());
    combined.extend_from_slice(iv_bytes.as_slice());
    combined.extend_from_slice(encrypted_bytes.as_slice());

    let combined_buffer = CryptographicBuffer::CreateFromByteArray(&combined)?;

    // Convert to base64 string (format: base64(IV || ciphertext))
    Ok(CryptographicBuffer::EncodeToBase64String(&combined_buffer)?.to_string())
}

/// Decrypt data using Windows Hello credential
fn decrypt_data(
    domain: &str,
    encrypted_data: &str,
    credential_result: &KeyCredentialRetrievalResult,
) -> Result<Vec<u8>> {
    let status = credential_result.Status()?;
    if status != KeyCredentialStatus::Success {
        return Err(Error::from(HRESULT(-1)));
    }

    let credential = credential_result.Credential()?;
    let challenge_buffer = CryptographicBuffer::ConvertStringToBinary(
        &HSTRING::from(domain),
        BinaryStringEncoding::Utf8,
    )?;

    // Sign the challenge to get the same key
    let signature = credential.RequestSignAsync(&challenge_buffer)?.get()?;
    let signature_status = signature.Status()?;

    if signature_status != KeyCredentialStatus::Success {
        return Err(Error::from(HRESULT(-1)));
    }

    let signature_result = signature.Result()?;

    // Use the signature to derive the decryption key
    let hash_provider = HashAlgorithmProvider::OpenAlgorithm(&HashAlgorithmNames::Sha256()?)?;
    let key_hash = hash_provider.HashData(&signature_result)?;

    // Create AES decryption provider
    let aes_provider =
        SymmetricKeyAlgorithmProvider::OpenAlgorithm(&SymmetricAlgorithmNames::AesCbcPkcs7()?)?;

    // Create symmetric key
    let key = aes_provider.CreateSymmetricKey(&key_hash)?;

    // Decode from base64
    let raw_buffer =
        CryptographicBuffer::DecodeFromBase64String(&HSTRING::from(encrypted_data))?;
    let mut raw_bytes: windows::core::Array<u8> = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(&raw_buffer, &mut raw_bytes)?;

    // New format: first 16 bytes are the random IV, remainder is ciphertext
    if raw_bytes.len() > 16 {
        let iv = CryptographicBuffer::CreateFromByteArray(&raw_bytes.as_slice()[..16])?;
        let ciphertext =
            CryptographicBuffer::CreateFromByteArray(&raw_bytes.as_slice()[16..])?;

        if let Ok(decrypted_buffer) =
            CryptographicEngine::Decrypt(&key, &ciphertext, Some(&iv))
        {
            let mut decrypted_bytes: windows::core::Array<u8> = windows::core::Array::new();
            CryptographicBuffer::CopyToByteArray(&decrypted_buffer, &mut decrypted_bytes)?;
            return Ok(decrypted_bytes.to_vec());
        }
    }

    // Fallback: legacy deterministic IV for data encrypted before this fix
    let iv_data = CryptographicBuffer::ConvertStringToBinary(
        &HSTRING::from(format!("IV_{}", domain)),
        BinaryStringEncoding::Utf8,
    )?;
    let iv_hash = hash_provider.HashData(&iv_data)?;

    let mut iv_bytes: windows::core::Array<u8> = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(&iv_hash, &mut iv_bytes)?;
    let legacy_iv_slice: Vec<u8> = iv_bytes.as_slice()[..16].to_vec();
    let legacy_iv = CryptographicBuffer::CreateFromByteArray(&legacy_iv_slice)?;

    let decrypted_buffer =
        CryptographicEngine::Decrypt(&key, &raw_buffer, Some(&legacy_iv))?;

    // Convert to bytes
    let mut decrypted_bytes: windows::core::Array<u8> = windows::core::Array::new();
    CryptographicBuffer::CopyToByteArray(&decrypted_buffer, &mut decrypted_bytes)?;

    Ok(decrypted_bytes.to_vec())
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

    pub fn has_data(&self, options: DataOptions) -> crate::Result<bool> {
        let domain = options.domain;
        let name = options.name;

        if domain.is_empty() || name.is_empty() {
            return Ok(false);
        }

        // Try to open the credential (without creating)
        let credential_result = match get_credential(&domain, false) {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };

        let status = credential_result.Status().map_err(|_| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some("Failed to check credential status".to_string()),
                data: (),
            }))
        })?;

        if status != KeyCredentialStatus::Success {
            return Ok(false);
        }

        // Check if there's data in the PasswordVault
        let vault = PasswordVault::new().map_err(|_| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some("Failed to access password vault".to_string()),
                data: (),
            }))
        })?;

        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        // Try to retrieve the credential without the password
        match vault.Retrieve(&resource, &username) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn get_data(&self, options: GetDataOptions) -> crate::Result<DataResponse> {
        let domain = options.domain.clone();
        let name = options.name.clone();

        if domain.is_empty() || name.is_empty() {
            return Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("invalidInput".to_string()),
                    message: Some("Domain and name must not be empty".to_string()),
                    data: (),
                }),
            ));
        }

        // Try to open the credential (without creating)
        let credential_result = get_credential(&domain, false).map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("credentialNotFound".to_string()),
                message: Some(format!("Failed to open credential: {:?}", e)),
                data: (),
            }))
        })?;

        let status = credential_result.Status().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to check credential status: {:?}", e)),
                data: (),
            }))
        })?;

        if status != KeyCredentialStatus::Success {
            return Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("credentialNotFound".to_string()),
                    message: Some("Credential not available".to_string()),
                    data: (),
                }),
            ));
        }

        // Access the PasswordVault
        let vault = PasswordVault::new().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to access password vault: {:?}", e)),
                data: (),
            }))
        })?;

        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        // Retrieve the credential with password
        let credential = vault.Retrieve(&resource, &username).map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("dataNotFound".to_string()),
                message: Some(format!("Failed to retrieve data: {:?}", e)),
                data: (),
            }))
        })?;

        // Get the password (encrypted data)
        credential.RetrievePassword().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to retrieve password: {:?}", e)),
                data: (),
            }))
        })?;

        let encrypted_data = credential.Password().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to get password: {:?}", e)),
                data: (),
            }))
        })?;

        // Decrypt the data
        let decrypted_data = decrypt_data(&domain, &encrypted_data.to_string(), &credential_result)
            .map_err(|e| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("decryptionFailed".to_string()),
                    message: Some(format!("Failed to decrypt data: {:?}", e)),
                    data: (),
                }))
            })?;

        // Convert decrypted bytes to string
        let data_string = String::from_utf8(decrypted_data).map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to convert data to string: {:?}", e)),
                data: (),
            }))
        })?;

        Ok(DataResponse {
            domain,
            name,
            data: data_string,
        })
    }

    pub fn set_data(&self, options: SetDataOptions) -> crate::Result<()> {
        let domain = options.domain;
        let name = options.name;
        let data = options.data;

        if domain.is_empty() || name.is_empty() {
            return Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("invalidInput".to_string()),
                    message: Some("Domain and name must not be empty".to_string()),
                    data: (),
                }),
            ));
        }

        // Create or replace the credential
        let credential_result = get_credential(&domain, true).map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("credentialCreationFailed".to_string()),
                message: Some(format!("Failed to create credential: {:?}", e)),
                data: (),
            }))
        })?;

        let status = credential_result.Status().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to check credential status: {:?}", e)),
                data: (),
            }))
        })?;

        if status != KeyCredentialStatus::Success {
            return Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("credentialCreationFailed".to_string()),
                    message: Some("Failed to create credential".to_string()),
                    data: (),
                }),
            ));
        }

        // Encrypt the data
        let encrypted_data =
            encrypt_data(&domain, data.as_bytes(), &credential_result).map_err(|e| {
                crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("encryptionFailed".to_string()),
                    message: Some(format!("Failed to encrypt data: {:?}", e)),
                    data: (),
                }))
            })?;

        // Access the PasswordVault
        let vault = PasswordVault::new().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to access password vault: {:?}", e)),
                data: (),
            }))
        })?;

        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);
        let password = HSTRING::from(&encrypted_data);

        // Try to remove existing credential if it exists
        if let Ok(existing) = vault.Retrieve(&resource, &username) {
            let _ = vault.Remove(&existing);
        }

        // Create new credential
        let credential = PasswordCredential::CreatePasswordCredential(
            &resource, &username, &password,
        )
        .map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to create password credential: {:?}", e)),
                data: (),
            }))
        })?;

        // Add to vault
        vault.Add(&credential).map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to store credential: {:?}", e)),
                data: (),
            }))
        })?;

        Ok(())
    }

    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        let domain = options.domain;
        let name = options.name;

        if domain.is_empty() || name.is_empty() {
            return Err(crate::Error::PluginInvoke(
                PluginInvokeError::InvokeRejected(ErrorResponse {
                    code: Some("invalidInput".to_string()),
                    message: Some("Domain and name must not be empty".to_string()),
                    data: (),
                }),
            ));
        }

        // Access the PasswordVault
        let vault = PasswordVault::new().map_err(|e| {
            crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                code: Some("internalError".to_string()),
                message: Some(format!("Failed to access password vault: {:?}", e)),
                data: (),
            }))
        })?;

        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        // Try to retrieve and remove the credential
        match vault.Retrieve(&resource, &username) {
            Ok(credential) => {
                vault.Remove(&credential).map_err(|e| {
                    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
                        code: Some("internalError".to_string()),
                        message: Some(format!("Failed to remove credential: {:?}", e)),
                        data: (),
                    }))
                })?;
                Ok(())
            }
            Err(_) => {
                // Credential doesn't exist, which is fine for remove
                Ok(())
            }
        }
    }
}
