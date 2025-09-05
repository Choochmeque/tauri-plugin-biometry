use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthOptions {
    /// Enables authentication using the device's password. This feature is available on both Android and iOS.
    pub allow_device_credential: Option<bool>,
    /// Label for the Cancel button. This feature is available on both Android and iOS.
    pub cancel_title: Option<String>,
    /// Specifies the text displayed on the fallback button if biometry authentication fails. This feature is available iOS only.
    pub fallback_title: Option<String>,
    /// Title indicating the purpose of biometry verification. This feature is available Android only.
    pub title: Option<String>,
    /// SubTitle providing contextual information of biometry verification. This feature is available Android only.
    pub subtitle: Option<String>,
    /// Specifies whether additional user confirmation is required, such as pressing a button after successful biometry authentication. This feature is available Android only.
    pub confirmation_required: Option<bool>,
}

#[derive(Serialize)]
pub struct AuthenticatePayload {
    pub reason: String,
    #[serde(flatten)]
    pub options: AuthOptions,
}

#[derive(Debug, Clone, serde_repr::Deserialize_repr, serde_repr::Serialize_repr)]
#[repr(u8)]
pub enum BiometryType {
    None = 0,
    TouchID = 1,
    FaceID = 2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub is_available: bool,
    pub biometry_type: BiometryType,
    pub error: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HasDataResponse {
    pub has_data: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataOptions {
    pub domain: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataResponse {
    pub domain: String,
    pub name: String,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDataOptions {
    pub domain: String,
    pub name: String,
    pub reason: String,
    pub cancel_title: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDataOptions {
    pub domain: String,
    pub name: String,
    pub data: String,
}

pub type RemoveDataOptions = DataOptions;
