use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime, WebviewWindow};

use crate::models::{
    AuthOptions, DataOptions, DataResponse, GetDataOptions, RemoveDataOptions, SetDataOptions,
    Status,
};

// Signature must match the cross-platform plugin contract — return type is
// fixed even though desktop init can't fail.
#[allow(clippy::unnecessary_wraps)]
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

/// Access to the biometry APIs.
pub struct Biometry<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Biometry<R> {
    // All desktop fallback methods just return "unsupported" without touching
    // per-instance state. Signatures match the cross-platform shape.
    #[allow(clippy::unused_self)]
    pub fn status(&self) -> crate::Result<Status> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }

    #[allow(clippy::unused_self)]
    pub fn authenticate(&self, _reason: String, _options: AuthOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }

    #[allow(clippy::unused_self)]
    pub fn has_data(&self, _options: DataOptions) -> crate::Result<bool> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }

    #[allow(clippy::unused_self)]
    pub fn get_data(
        &self,
        _window: WebviewWindow<R>,
        _options: GetDataOptions,
    ) -> crate::Result<DataResponse> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }

    #[allow(clippy::unused_self)]
    pub fn set_data(
        &self,
        _window: WebviewWindow<R>,
        _options: SetDataOptions,
    ) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }

    #[allow(clippy::unused_self)]
    pub fn remove_data(&self, _options: RemoveDataOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on this platform",
        )))
    }
}
