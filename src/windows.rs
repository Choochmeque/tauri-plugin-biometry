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
use tauri::{plugin::PluginApi, AppHandle, Runtime, WebviewWindow};

use windows_future::IAsyncOperation;

use windows::{
    core::{factory, Error as WinError, Interface, BOOL, GUID, HRESULT, HSTRING, PCWSTR},
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Security::Credentials::{PasswordCredential, PasswordVault},
    Win32::Foundation::HWND,
    Win32::Networking::WindowsWebServices::{
        WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential,
        WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation, WEBAUTHN_ASSERTION,
        WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, WEBAUTHN_CLIENT_DATA,
        WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        WEBAUTHN_CREDENTIALS, WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_EX,
        WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_EXTENSIONS,
        WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES,
        WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
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

// Signature must match the cross-platform plugin contract — return type is
// fixed even though Windows init can't fail.
#[allow(clippy::unnecessary_wraps)]
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

struct WideStr(Vec<u16>);
impl WideStr {
    fn new(s: &str) -> Self {
        Self(
            std::ffi::OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect(),
        )
    }

    fn pcwstr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
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

fn u32_len(n: usize) -> Result<u32, WinError> {
    u32::try_from(n).map_err(|_| WinError::from(HRESULT(-1)))
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

// Binds the ciphertext to the full logical record key — `version`, `domain`,
// `name`, `salt`, and `credential_id`. Without all five, a blob written for
// (domain=X, name=A) could be replayed at (domain=X, name=B) — or under a
// different salt — and still pass AES-GCM authentication.
fn aad_for(
    domain: &str,
    name: &str,
    salt: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Aad<'a> {
        v: u8,
        domain: &'a str,
        name: &'a str,
        #[serde(with = "b64_field")]
        salt: Vec<u8>,
        #[serde(with = "b64_field")]
        cred: Vec<u8>,
    }
    serde_json::to_vec(&Aad {
        v: BLOB_VERSION,
        domain,
        name,
        salt: salt.to_vec(),
        cred: credential_id.to_vec(),
    })
}

// -------------------- WebAuthn helpers --------------------

// Hand-rolled WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS at version 8.
// `windows` 0.61 only models fields up through v6 (ending at `bEnablePrf`),
// but we need v8's `pPRFGlobalEval` to evaluate the PRF at credential
// creation and avoid a second Hello prompt for the initial setData. Layout
// must match webauthn.h exactly.
#[repr(C)]
#[allow(non_snake_case)]
struct MakeCredOptionsV8 {
    dwVersion: u32,
    dwTimeoutMilliseconds: u32,
    CredentialList: WEBAUTHN_CREDENTIALS,
    Extensions: WEBAUTHN_EXTENSIONS,
    dwAuthenticatorAttachment: u32,
    bRequireResidentKey: BOOL,
    dwUserVerificationRequirement: u32,
    dwAttestationConveyancePreference: u32,
    dwFlags: u32,
    // v2+
    pCancellationId: *mut GUID,
    // v3+
    pExcludeCredentialList: *mut WEBAUTHN_CREDENTIAL_LIST,
    // v4+
    dwEnterpriseAttestation: u32,
    dwLargeBlobSupport: u32,
    bPreferResidentKey: BOOL,
    // v5+
    bBrowserInPrivateMode: BOOL,
    // v6+
    bEnablePrf: BOOL,
    // v7+
    pLinkedDevice: *mut c_void,
    cbJsonExt: u32,
    pbJsonExt: *mut u8,
    // v8+
    pPRFGlobalEval: *mut WEBAUTHN_HMAC_SECRET_SALT,
    cCredentialHints: u32,
    ppwszCredentialHints: *mut PCWSTR,
    bThirdPartyPayment: BOOL,
}

// Hand-rolled WEBAUTHN_CREDENTIAL_ATTESTATION at v7+ so we can read
// `pHmacSecret`, which is where webauthn.dll places the PRF output produced
// by `pPRFGlobalEval` at create time. windows-rs stops at the v6 layout.
#[repr(C)]
#[allow(non_snake_case)]
struct CredentialAttestationV7 {
    dwVersion: u32,
    pwszFormatType: PCWSTR,
    cbAuthenticatorData: u32,
    pbAuthenticatorData: *mut u8,
    cbAttestation: u32,
    pbAttestation: *mut u8,
    dwAttestationDecodeType: u32,
    pvAttestationDecode: *mut c_void,
    cbAttestationObject: u32,
    pbAttestationObject: *mut u8,
    cbCredentialId: u32,
    pbCredentialId: *mut u8,
    Extensions: WEBAUTHN_EXTENSIONS,
    dwUsedTransport: u32,
    bEpAtt: BOOL,
    bLargeBlobSupported: BOOL,
    bResidentKey: BOOL,
    bPrfEnabled: BOOL,
    cbUnsignedExtensionOutputs: u32,
    pbUnsignedExtensionOutputs: *mut u8,
    // v7+
    pHmacSecret: *mut WEBAUTHN_HMAC_SECRET_SALT,
    bThirdPartyPayment: BOOL,
}

const MAKE_CRED_OPTIONS_VERSION_8: u32 = 8;

// RAII wrappers so early-return paths automatically free the heap-allocated
// structs webauthn.dll hands back, instead of needing a `Free` call before
// every `return Err(...)`.
struct AttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);

impl AttestationGuard {
    const fn as_ptr(&self) -> *mut WEBAUTHN_CREDENTIAL_ATTESTATION {
        self.0
    }
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for AttestationGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WebAuthNFreeCredentialAttestation(Some(self.0)) };
        }
    }
}

struct AssertionGuard(*mut WEBAUTHN_ASSERTION);

impl AssertionGuard {
    const fn as_ptr(&self) -> *mut WEBAUTHN_ASSERTION {
        self.0
    }
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for AssertionGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WebAuthNFreeAssertion(self.0) };
        }
    }
}

// Hand-declared because `windows` 0.61 doesn't expose this interop interface.
// Used to invoke `UserConsentVerifier` with an HWND parent so the Hello
// dialog is owned by our window instead of appearing behind it (which is
// what makes the WinRT-only `RequestVerificationAsync` look like a hang).
//
// Inherits from `IUnknown` rather than `IInspectable` because
// `windows-core` 0.61 doesn't publish `IInspectable_Impl` (only
// `IUnknown_Impl`). The 3 IInspectable slots are declared manually so the
// vtable layout still matches: IUnknown (3 slots, generated by the macro)
// + IInspectable (3 slots, here) + our method.
// COM method names match the Windows ABI verbatim; the macro expansion also
// produces reference-to-reference transmutes as part of the IUnknown-derived
// vtable plumbing. Both are suppressed module-wide so they don't leak out
// into the rest of the file.
mod interop {
    #![allow(non_snake_case, clippy::transmute_ptr_to_ptr)]

    use std::ffi::c_void;
    use windows::core::{GUID, HRESULT, HSTRING};
    use windows::Win32::Foundation::HWND;

    #[windows::core::interface("39E050C3-4E74-441A-8DC0-B81104DF949C")]
    pub unsafe trait IUserConsentVerifierInterop: windows_core::IUnknown {
        pub unsafe fn GetIids(&self, iid_count: *mut u32, iids: *mut *mut GUID) -> HRESULT;
        pub unsafe fn GetRuntimeClassName(
            &self,
            class_name: *mut std::mem::ManuallyDrop<HSTRING>,
        ) -> HRESULT;
        pub unsafe fn GetTrustLevel(&self, trust_level: *mut i32) -> HRESULT;
        pub unsafe fn RequestVerificationForWindowAsync(
            &self,
            app_window: HWND,
            message: std::mem::ManuallyDrop<HSTRING>,
            riid: *const GUID,
            async_operation: *mut *mut c_void,
        ) -> HRESULT;
    }
}

use interop::IUserConsentVerifierInterop;

// Creates a Hello-bound credential AND evaluates the PRF for `salt` in the
// same operation — collapses the prior MakeCredential + GetAssertion pair
// into one Hello prompt for first-time enrollment of a domain.
#[allow(clippy::too_many_lines)]
fn make_webauthn_credential_with_prf(
    hwnd: HWND,
    rp_id_str: &str,
    user_label: &str,
    salt: &[u8; PRF_SALT_LEN],
) -> Result<(Vec<u8>, [u8; PRF_OUT_LEN]), WinError> {
    let rp_id_w = WideStr::new(rp_id_str);
    let rp_name_w = WideStr::new(rp_id_str);
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: rp_id_w.pcwstr(),
        pwszName: rp_name_w.pcwstr(),
        pwszIcon: PCWSTR::null(),
    };

    let mut user_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut user_id);
    let user_name_w = WideStr::new(user_label);
    let user_display_w = WideStr::new(user_label);
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: 16,
        pbId: user_id.as_mut_ptr(),
        pwszName: user_name_w.pcwstr(),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: user_display_w.pcwstr(),
    };

    let challenge: [u8; 32] = rand::random();
    let challenge_b64 = B64.encode(challenge);
    let client_data_json = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge_b64}\",\"origin\":\"{rp_id_str}\"}}"
    );
    let mut client_data_bytes = client_data_json.into_bytes();
    let hash_alg_w = WideStr::new("SHA-256");
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32_len(client_data_bytes.len())?,
        pbClientDataJSON: client_data_bytes.as_mut_ptr(),
        pwszHashAlgId: hash_alg_w.pcwstr(),
    };

    let public_key_type_w = WideStr::new("public-key");
    let mut params = [
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: public_key_type_w.pcwstr(),
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        },
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: public_key_type_w.pcwstr(),
            lAlg: WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
        },
    ];
    let cred_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: 2,
        pCredentialParameters: params.as_mut_ptr(),
    };

    // PRF eval input — populated into pPRFGlobalEval below.
    let mut salt_bytes = salt.to_vec();
    let mut prf_eval = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: 32,
        pbFirst: salt_bytes.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: ptr::null_mut(),
    };

    let mut options: MakeCredOptionsV8 = unsafe { std::mem::zeroed() };
    options.dwVersion = MAKE_CRED_OPTIONS_VERSION_8;
    options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.bRequireResidentKey = BOOL(0);
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    options.dwFlags = 0;
    options.bEnablePrf = BOOL(1);
    options.pPRFGlobalEval = &mut prf_eval;

    let options_ptr =
        std::ptr::addr_of!(options).cast::<WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS>();

    let attestation = AttestationGuard(unsafe {
        WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &rp,
            &user,
            &cred_params,
            &client_data,
            Some(options_ptr),
        )?
    });

    if attestation.is_null() {
        return Err(WinError::from(HRESULT(-1)));
    }

    unsafe {
        let att = &*attestation.as_ptr().cast::<CredentialAttestationV7>();
        if att.dwVersion < 7 {
            return Err(WinError::from(HRESULT(-1)));
        }
        if att.pbCredentialId.is_null() || att.cbCredentialId == 0 {
            return Err(WinError::from(HRESULT(-1)));
        }
        let cred_slice =
            std::slice::from_raw_parts(att.pbCredentialId, att.cbCredentialId as usize);
        let credential_id = cred_slice.to_vec();

        if att.pHmacSecret.is_null() {
            return Err(WinError::from(HRESULT(-1)));
        }
        let hmac = &*att.pHmacSecret;
        if hmac.pbFirst.is_null() || hmac.cbFirst as usize != PRF_OUT_LEN {
            return Err(WinError::from(HRESULT(-1)));
        }
        let mut prf_out = [0u8; PRF_OUT_LEN];
        std::ptr::copy_nonoverlapping(hmac.pbFirst, prf_out.as_mut_ptr(), PRF_OUT_LEN);

        Ok((credential_id, prf_out))
    }
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
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_b64}\",\"origin\":\"{rp_id_str}\"}}"
    );
    let mut client_data_bytes = client_data_json.into_bytes();
    let hash_alg_w = WideStr::new("SHA-256");
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32_len(client_data_bytes.len())?,
        pbClientDataJSON: client_data_bytes.as_mut_ptr(),
        pwszHashAlgId: hash_alg_w.pcwstr(),
    };

    let public_key_type_w = WideStr::new("public-key");
    let mut cred_id_bytes = credential_id.to_vec();
    let mut cred_ex = WEBAUTHN_CREDENTIAL_EX {
        dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
        cbId: u32_len(cred_id_bytes.len())?,
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
        cbFirst: 32,
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
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
    options.dwTimeoutMilliseconds = WEBAUTHN_TIMEOUT_MS;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = 0;
    options.pAllowCredentialList = &mut allow_list;
    options.pHmacSecretSaltValues = &mut salt_values;

    let assertion = AssertionGuard(unsafe {
        WebAuthNAuthenticatorGetAssertion(hwnd, rp_id_w.pcwstr(), &client_data, Some(&options))?
    });

    if assertion.is_null() {
        return Err(WinError::from(HRESULT(-1)));
    }

    unsafe {
        let inner = &*assertion.as_ptr();
        if inner.pHmacSecret.is_null() {
            return Err(WinError::from(HRESULT(-1)));
        }
        let secret = &*inner.pHmacSecret;
        if secret.pbFirst.is_null() || secret.cbFirst as usize != PRF_OUT_LEN {
            return Err(WinError::from(HRESULT(-1)));
        }
        let slice = std::slice::from_raw_parts(secret.pbFirst, PRF_OUT_LEN);
        let mut out = [0u8; PRF_OUT_LEN];
        out.copy_from_slice(slice);
        Ok(out)
    }
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
        let Ok(password) = entry.Password() else {
            continue;
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
    // Methods that don't touch self use global Windows APIs (UserConsentVerifier
    // / PasswordVault). Signatures match the cross-platform shape.
    #[allow(clippy::unused_self)]
    pub fn status(&self) -> crate::Result<Status> {
        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|async_op| async_op.get())
            .map_err(|e| {
                reject_fmt("internalError", "Failed to check biometry availability", &e)
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

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn authenticate(
        &self,
        window: WebviewWindow<R>,
        reason: String,
        _options: AuthOptions,
    ) -> crate::Result<()> {
        let hwnd = window
            .hwnd()
            .map_err(|e| reject_fmt("internalError", "resolve window hwnd", &e))?;

        // Use the interop interface to parent the Hello dialog to our HWND.
        // Without this, RequestVerificationAsync's prompt appears behind the
        // app window — looks like a hang because the user can't see it.
        let interop: IUserConsentVerifierInterop =
            factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
                .map_err(|e| reject_fmt("internalError", "get IUserConsentVerifierInterop", &e))?;

        let message = std::mem::ManuallyDrop::new(HSTRING::from(reason));
        let mut async_op_ptr: *mut c_void = std::ptr::null_mut();
        let hr = unsafe {
            interop.RequestVerificationForWindowAsync(
                hwnd,
                message,
                &IAsyncOperation::<UserConsentVerificationResult>::IID,
                &mut async_op_ptr,
            )
        };
        hr.ok()
            .map_err(|e| reject_fmt("internalError", "RequestVerificationForWindowAsync", &e))?;
        if async_op_ptr.is_null() {
            return Err(reject("internalError", "null IAsyncOperation pointer"));
        }
        let async_op =
            unsafe { IAsyncOperation::<UserConsentVerificationResult>::from_raw(async_op_ptr) };
        let result = async_op
            .get()
            .map_err(|e| reject_fmt("internalError", "Failed to request user verification", &e))?;

        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::DeviceBusy => {
                Err(reject("systemCancel", "Device is busy"))
            }
            UserConsentVerificationResult::DeviceNotPresent => {
                Err(reject("biometryNotAvailable", "No biometric device found"))
            }
            UserConsentVerificationResult::DisabledByPolicy => Err(reject(
                "biometryNotAvailable",
                "Biometric authentication is disabled by policy",
            )),
            UserConsentVerificationResult::NotConfiguredForUser => Err(reject(
                "biometryNotEnrolled",
                "Biometric authentication is not configured for the user",
            )),
            UserConsentVerificationResult::Canceled => Err(reject(
                "userCancel",
                "Authentication was canceled by the user",
            )),
            UserConsentVerificationResult::RetriesExhausted => Err(reject(
                "biometryLockout",
                "Too many failed authentication attempts",
            )),
            _ => Err(reject("authenticationFailed", "Authentication failed")),
        }
    }

    #[allow(
        clippy::unused_self,
        clippy::needless_pass_by_value,
        clippy::unnecessary_wraps
    )]
    pub fn has_data(&self, options: DataOptions) -> crate::Result<bool> {
        let domain = options.domain;
        let name = options.name;

        if domain.is_empty() || name.is_empty() {
            return Ok(false);
        }
        if validate_domain(&domain).is_err() {
            return Ok(false);
        }

        let Ok(vault) = PasswordVault::new() else {
            return Ok(false);
        };
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);
        Ok(vault.Retrieve(&resource, &username).is_ok())
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn get_data(
        &self,
        window: WebviewWindow<R>,
        options: GetDataOptions,
    ) -> crate::Result<DataResponse> {
        let domain = options.domain;
        let name = options.name;

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
        let aad = aad_for(&domain, &name, &blob.salt, &blob.cred)
            .map_err(|e| reject("internalError", &format!("aad: {e}")))?;
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

    #[allow(clippy::needless_pass_by_value)]
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

        let mut salt = [0u8; PRF_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut iv = [0u8; AES_GCM_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut iv);

        let (credential_id, prf_out) = match find_existing_credential_id_for_domain(&domain) {
            Some(id) => {
                let prf = get_assertion_prf(hwnd, &rp_id_str, &id, &salt)
                    .map_err(|e| reject_fmt("authenticationFailed", "webauthn assertion", &e))?;
                (id, prf)
            }
            None => {
                make_webauthn_credential_with_prf(hwnd, &rp_id_str, &name, &salt).map_err(|e| {
                    reject_fmt("credentialCreationFailed", "webauthn make credential", &e)
                })?
            }
        };

        let cipher = Aes256Gcm::new_from_slice(&prf_out)
            .map_err(|e| reject("internalError", &format!("aes key init: {e}")))?;
        let nonce = Nonce::from_slice(&iv);
        let aad = aad_for(&domain, &name, &salt, &credential_id)
            .map_err(|e| reject("internalError", &format!("aad: {e}")))?;
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

    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        let domain = options.domain;
        let name = options.name;

        if domain.is_empty() || name.is_empty() {
            return Err(reject("invalidInput", "Domain and name must not be empty"));
        }
        // Same validation as set_data / get_data so a caller with remove_data
        // permission can't delete vault entries outside the plugin's intended
        // domain shape.
        validate_domain(&domain).map_err(|m| reject("invalidInput", m))?;

        let vault =
            PasswordVault::new().map_err(|e| reject_fmt("internalError", "vault open", &e))?;
        let resource = HSTRING::from(&domain);
        let username = HSTRING::from(&name);

        let Ok(cred) = vault.Retrieve(&resource, &username) else {
            return Ok(());
        };
        vault
            .Remove(&cred)
            .map_err(|e| reject_fmt("internalError", "vault remove", &e))
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
