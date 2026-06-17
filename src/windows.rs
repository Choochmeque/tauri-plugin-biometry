use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tauri::{plugin::PluginApi, AppHandle, Manager, Runtime, WebviewWindow};

use windows::{
    core::{Error as WinError, BOOL, HRESULT, HSTRING, PCWSTR},
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Security::Credentials::{PasswordCredential, PasswordVault},
    Win32::Foundation::HWND,
    Win32::Networking::WindowsWebServices::{
        WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential,
        WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation,
        WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, WEBAUTHN_CLIENT_DATA,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_EXTENSION, WEBAUTHN_EXTENSIONS,
        WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES,
        WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION,
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
    },
    Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, FindWindowW, IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE,
    },
};

use crate::error::{ErrorResponse, PluginInvokeError};
use crate::models::{
    AuthOptions, BiometryType, DataOptions, DataResponse, GetDataOptions, RemoveDataOptions,
    SetDataOptions, Status,
};

const PLUGIN_RP_PREFIX: &str = "io.tauri.plugin.biometry";
const BLOB_VERSION: u8 = 0x01;
const PRF_SALT_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;
const PRF_OUT_LEN: usize = 32;
const MAX_DOMAIN_LEN: usize = 64;
const WEBAUTHN_TIMEOUT_MS: u32 = 60_000;

const MAKE_CRED_OPTIONS_VERSION: u32 = 3;
const GET_ASSERT_OPTIONS_VERSION: u32 = 6;
const CLIENT_DATA_VERSION: u32 = 1;
const RP_ENTITY_VERSION: u32 = 1;
const USER_ENTITY_VERSION: u32 = 1;
const COSE_CRED_PARAM_VERSION: u32 = 1;
const CRED_EX_VERSION: u32 = 1;

const COSE_ALG_ES256: i32 = -7;
const COSE_ALG_RS256: i32 = -257;
const ATTESTATION_NONE: u32 = 0;

// Signature must match the cross-platform plugin contract — return type is
// fixed even though Windows init can't fail.
#[allow(clippy::unnecessary_wraps)]
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

#[inline]
fn to_wide_z(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct WideStr(Vec<u16>);
impl WideStr {
    fn new(s: &str) -> Self {
        Self(to_wide_z(s))
    }
    fn pcwstr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
}

fn try_focus_hello_dialog_once() -> bool {
    let cls = to_wide_z("Credential Dialog Xaml Host");
    unsafe {
        let hwnd = FindWindowW(PCWSTR(cls.as_ptr()), PCWSTR::null());
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

fn nudge_hello_dialog_focus_async(retries: u32, delay_ms: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        for _ in 0..retries {
            if try_focus_hello_dialog_once() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    });
}

fn validate_domain(domain: &str) -> Result<(), &'static str> {
    if domain.is_empty() {
        return Err("domain must not be empty");
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err("domain exceeds maximum length");
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err("domain must match [A-Za-z0-9._-]");
    }
    Ok(())
}

fn rp_id_for(app_identifier: &str, domain: &str) -> String {
    format!("{PLUGIN_RP_PREFIX}.{app_identifier}.{domain}")
}

// -------------------- blob format --------------------

mod b64_field {
    use super::B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct Blob {
    v: u8,
    #[serde(with = "b64_field")]
    cred: Vec<u8>,
    #[serde(with = "b64_field")]
    salt: Vec<u8>,
    #[serde(with = "b64_field")]
    iv: Vec<u8>,
    #[serde(with = "b64_field")]
    ct: Vec<u8>,
}

fn decode_blob(data: &str) -> Result<Blob, String> {
    let blob: Blob = serde_json::from_str(data).map_err(|e| format!("blob parse: {e}"))?;
    if blob.v != BLOB_VERSION {
        return Err(
            "blob version mismatch — stored data is from a previous plugin version; remove and re-enroll"
                .to_string(),
        );
    }
    if blob.salt.len() != PRF_SALT_LEN {
        return Err(format!(
            "blob salt has wrong length: {} (expected {PRF_SALT_LEN})",
            blob.salt.len()
        ));
    }
    if blob.iv.len() != AES_GCM_NONCE_LEN {
        return Err(format!(
            "blob iv has wrong length: {} (expected {AES_GCM_NONCE_LEN})",
            blob.iv.len()
        ));
    }
    if blob.cred.is_empty() {
        return Err("blob credential id is empty".to_string());
    }
    Ok(blob)
}

fn aad_for(credential_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + credential_id.len());
    aad.push(BLOB_VERSION);
    aad.extend_from_slice(credential_id);
    aad
}

// -------------------- WebAuthn helpers --------------------

fn make_webauthn_credential(
    hwnd: HWND,
    rp_id_str: &str,
    user_label: &str,
) -> Result<Vec<u8>, WinError> {
    let rp_id_w = WideStr::new(rp_id_str);
    let rp_name_w = WideStr::new(rp_id_str);
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: RP_ENTITY_VERSION,
        pwszId: rp_id_w.pcwstr(),
        pwszName: rp_name_w.pcwstr(),
        pwszIcon: PCWSTR::null(),
    };

    let mut user_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut user_id);
    let user_name_w = WideStr::new(user_label);
    let user_display_w = WideStr::new(user_label);
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: USER_ENTITY_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: user_name_w.pcwstr(),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: user_display_w.pcwstr(),
    };

    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = B64.encode(challenge);
    let client_data_json = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        challenge_b64, rp_id_str
    );
    let mut client_data_bytes = client_data_json.into_bytes();
    let hash_alg_w = WideStr::new("SHA-256");
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: CLIENT_DATA_VERSION,
        cbClientDataJSON: client_data_bytes.len() as u32,
        pbClientDataJSON: client_data_bytes.as_mut_ptr(),
        pwszHashAlgId: hash_alg_w.pcwstr(),
    };

    let public_key_type_w = WideStr::new("public-key");
    let mut params = [
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: COSE_CRED_PARAM_VERSION,
            pwszCredentialType: public_key_type_w.pcwstr(),
            lAlg: COSE_ALG_ES256,
        },
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: COSE_CRED_PARAM_VERSION,
            pwszCredentialType: public_key_type_w.pcwstr(),
            lAlg: COSE_ALG_RS256,
        },
    ];
    let cred_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: params.len() as u32,
        pCredentialParameters: params.as_mut_ptr(),
    };

    let hmac_secret_id_w = WideStr::new("hmac-secret");
    let mut hmac_enable: BOOL = BOOL(1);
    let mut ext_list = [WEBAUTHN_EXTENSION {
        pwszExtensionIdentifier: hmac_secret_id_w.pcwstr(),
        cbExtension: std::mem::size_of::<BOOL>() as u32,
        pvExtension: &mut hmac_enable as *mut _ as *mut c_void,
    }];
    let extensions = WEBAUTHN_EXTENSIONS {
        cExtensions: ext_list.len() as u32,
        pExtensions: ext_list.as_mut_ptr(),
    };

    let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = unsafe { std::mem::zeroed() };
    options.dwVersion = MAKE_CRED_OPTIONS_VERSION;
    options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
    options.Extensions = extensions;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.bRequireResidentKey = BOOL(0);
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = ATTESTATION_NONE;
    options.dwFlags = 0;

    nudge_hello_dialog_focus_async(5, 250);

    let attestation_ptr = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &rp,
            &user,
            &cred_params,
            &client_data,
            Some(&options),
        )?
    };

    if attestation_ptr.is_null() {
        return Err(WinError::from(HRESULT(-1)));
    }

    let result = unsafe {
        let att = &*attestation_ptr;
        if att.pbCredentialId.is_null() || att.cbCredentialId == 0 {
            WebAuthNFreeCredentialAttestation(attestation_ptr);
            return Err(WinError::from(HRESULT(-1)));
        }
        let slice = std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize);
        let v = slice.to_vec();
        WebAuthNFreeCredentialAttestation(attestation_ptr);
        v
    };

    Ok(result)
}

fn get_assertion_prf(
    hwnd: HWND,
    rp_id_str: &str,
    credential_id: &[u8],
    salt: &[u8; PRF_SALT_LEN],
) -> Result<[u8; PRF_OUT_LEN], WinError> {
    let rp_id_w = WideStr::new(rp_id_str);

    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = B64.encode(challenge);
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
        challenge_b64, rp_id_str
    );
    let mut client_data_bytes = client_data_json.into_bytes();
    let hash_alg_w = WideStr::new("SHA-256");
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: CLIENT_DATA_VERSION,
        cbClientDataJSON: client_data_bytes.len() as u32,
        pbClientDataJSON: client_data_bytes.as_mut_ptr(),
        pwszHashAlgId: hash_alg_w.pcwstr(),
    };

    let public_key_type_w = WideStr::new("public-key");
    let mut cred_id_bytes = credential_id.to_vec();
    let mut cred_ex = WEBAUTHN_CREDENTIAL_EX {
        dwVersion: CRED_EX_VERSION,
        cbId: cred_id_bytes.len() as u32,
        pbId: cred_id_bytes.as_mut_ptr(),
        pwszCredentialType: public_key_type_w.pcwstr(),
        dwTransports: 0,
    };
    let mut cred_ex_ptr: *mut WEBAUTHN_CREDENTIAL_EX = &mut cred_ex;
    let mut allow_list = WEBAUTHN_CREDENTIAL_LIST {
        cCredentials: 1,
        ppCredentials: &mut cred_ex_ptr,
    };

    let mut salt_bytes = salt.to_vec();
    let mut global_salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: salt_bytes.len() as u32,
        pbFirst: salt_bytes.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: ptr::null_mut(),
    };
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &mut global_salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: ptr::null_mut(),
    };

    let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
    options.dwVersion = GET_ASSERT_OPTIONS_VERSION;
    options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = 0;
    options.pAllowCredentialList = &mut allow_list;
    options.pHmacSecretSaltValues = &mut salt_values;

    nudge_hello_dialog_focus_async(5, 250);

    let assertion_ptr = unsafe {
        WebAuthNAuthenticatorGetAssertion(hwnd, rp_id_w.pcwstr(), &client_data, Some(&options))?
    };

    if assertion_ptr.is_null() {
        return Err(WinError::from(HRESULT(-1)));
    }

    let prf_out = unsafe {
        let assertion = &*assertion_ptr;
        if assertion.pHmacSecret.is_null() {
            WebAuthNFreeAssertion(assertion_ptr);
            return Err(WinError::from(HRESULT(-1)));
        }
        let secret = &*assertion.pHmacSecret;
        if secret.pbFirst.is_null() || secret.cbFirst as usize != PRF_OUT_LEN {
            WebAuthNFreeAssertion(assertion_ptr);
            return Err(WinError::from(HRESULT(-1)));
        }
        let slice = std::slice::from_raw_parts(secret.pbFirst, PRF_OUT_LEN);
        let mut out = [0u8; PRF_OUT_LEN];
        out.copy_from_slice(slice);
        WebAuthNFreeAssertion(assertion_ptr);
        out
    };

    Ok(prf_out)
}

// -------------------- PasswordVault helpers --------------------

fn find_existing_credential_id_for_domain(domain: &str) -> Option<Vec<u8>> {
    let vault = PasswordVault::new().ok()?;
    let resource = HSTRING::from(domain);
    let entries = vault.FindAllByResource(&resource).ok()?;
    let count = entries.Size().ok()?;
    for i in 0..count {
        let entry = entries.GetAt(i).ok()?;
        if entry.RetrievePassword().is_err() {
            continue;
        }
        let password = match entry.Password() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(blob) = decode_blob(&password.to_string()) {
            return Some(blob.cred);
        }
    }
    None
}

// -------------------- Biometry struct --------------------

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
        if validate_domain(&domain).is_err() {
            return Ok(false);
        }

        let vault = match PasswordVault::new() {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);
        Ok(vault.Retrieve(&resource, &username).is_ok())
    }

    pub fn get_data(
        &self,
        window: WebviewWindow<R>,
        options: GetDataOptions,
    ) -> crate::Result<DataResponse> {
        let domain = options.domain.clone();
        let name = options.name.clone();

        if domain.is_empty() || name.is_empty() {
            return Err(reject("invalidInput", "Domain and name must not be empty"));
        }
        validate_domain(&domain).map_err(|m| reject("invalidInput", m))?;

        let hwnd = window
            .hwnd()
            .map_err(|e| reject_fmt("internalError", "resolve window hwnd", &e))?;

        let vault =
            PasswordVault::new().map_err(|e| reject_fmt("internalError", "vault open", &e))?;
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        let credential = vault
            .Retrieve(&resource, &username)
            .map_err(|e| reject_fmt("dataNotFound", "vault retrieve", &e))?;
        credential
            .RetrievePassword()
            .map_err(|e| reject_fmt("internalError", "retrieve password", &e))?;
        let stored = credential
            .Password()
            .map_err(|e| reject_fmt("internalError", "get password", &e))?;

        let blob =
            decode_blob(&stored.to_string()).map_err(|m| reject("dataNeedsReenrollment", &m))?;

        let salt_arr: &[u8; PRF_SALT_LEN] = blob
            .salt
            .as_slice()
            .try_into()
            .map_err(|_| reject("internalError", "salt length mismatch"))?;

        let rp_id_str = rp_id_for(&self.0.config().identifier, &domain);

        let prf_out = get_assertion_prf(hwnd, &rp_id_str, &blob.cred, salt_arr)
            .map_err(|e| reject_fmt("authenticationFailed", "webauthn assertion", &e))?;

        let cipher = Aes256Gcm::new_from_slice(&prf_out)
            .map_err(|e| reject("internalError", &format!("aes key init: {e}")))?;
        let nonce = Nonce::from_slice(&blob.iv);
        let aad = aad_for(&blob.cred);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &blob.ct,
                    aad: &aad,
                },
            )
            .map_err(|e| reject("decryptionFailed", &format!("aes-gcm decrypt: {e}")))?;

        let data_string = String::from_utf8(plaintext)
            .map_err(|e| reject("internalError", &format!("utf-8: {e}")))?;

        Ok(DataResponse {
            domain,
            name,
            data: data_string,
        })
    }

    pub fn set_data(&self, window: WebviewWindow<R>, options: SetDataOptions) -> crate::Result<()> {
        let domain = options.domain;
        let name = options.name;
        let data = options.data;

        if domain.is_empty() || name.is_empty() {
            return Err(reject("invalidInput", "Domain and name must not be empty"));
        }
        validate_domain(&domain).map_err(|m| reject("invalidInput", m))?;

        let hwnd = window
            .hwnd()
            .map_err(|e| reject_fmt("internalError", "resolve window hwnd", &e))?;

        let rp_id_str = rp_id_for(&self.0.config().identifier, &domain);

        let credential_id = match find_existing_credential_id_for_domain(&domain) {
            Some(id) => id,
            None => make_webauthn_credential(hwnd, &rp_id_str, &name).map_err(|e| {
                reject_fmt("credentialCreationFailed", "webauthn make credential", &e)
            })?,
        };

        let mut salt = [0u8; PRF_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut iv = [0u8; AES_GCM_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut iv);

        let prf_out = get_assertion_prf(hwnd, &rp_id_str, &credential_id, &salt)
            .map_err(|e| reject_fmt("authenticationFailed", "webauthn assertion", &e))?;

        let cipher = Aes256Gcm::new_from_slice(&prf_out)
            .map_err(|e| reject("internalError", &format!("aes key init: {e}")))?;
        let nonce = Nonce::from_slice(&iv);
        let aad = aad_for(&credential_id);
        let ciphertext_with_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| reject("encryptionFailed", &format!("aes-gcm encrypt: {e}")))?;

        let blob = Blob {
            v: BLOB_VERSION,
            cred: credential_id,
            salt: salt.to_vec(),
            iv: iv.to_vec(),
            ct: ciphertext_with_tag,
        };
        let stored = serde_json::to_string(&blob)
            .map_err(|e| reject("internalError", &format!("encode blob: {e}")))?;

        let vault =
            PasswordVault::new().map_err(|e| reject_fmt("internalError", "vault open", &e))?;
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);
        let password = HSTRING::from(&stored);

        if let Ok(existing) = vault.Retrieve(&resource, &username) {
            let _ = vault.Remove(&existing);
        }

        let cred = PasswordCredential::CreatePasswordCredential(&resource, &username, &password)
            .map_err(|e| reject_fmt("internalError", "create password credential", &e))?;
        vault
            .Add(&cred)
            .map_err(|e| reject_fmt("internalError", "vault add", &e))?;

        Ok(())
    }

    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        let domain = options.domain;
        let name = options.name;

        if domain.is_empty() || name.is_empty() {
            return Err(reject("invalidInput", "Domain and name must not be empty"));
        }

        let vault =
            PasswordVault::new().map_err(|e| reject_fmt("internalError", "vault open", &e))?;
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        match vault.Retrieve(&resource, &username) {
            Ok(cred) => vault
                .Remove(&cred)
                .map_err(|e| reject_fmt("internalError", "vault remove", &e)),
            Err(_) => Ok(()),
        }
    }
}

fn reject(code: &str, message: &str) -> crate::Error {
    crate::Error::PluginInvoke(PluginInvokeError::InvokeRejected(ErrorResponse {
        code: Some(code.to_string()),
        message: Some(message.to_string()),
        data: (),
    }))
}

fn reject_fmt<E: std::fmt::Debug>(code: &str, ctx: &str, err: &E) -> crate::Error {
    reject(code, &format!("{ctx}: {err:?}"))
}
