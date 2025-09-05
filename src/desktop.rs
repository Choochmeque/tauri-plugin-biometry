use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    Ok(Biometry(app.clone()))
}

/// Access to the biometry APIs.
pub struct Biometry<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Biometry<R> {
    pub fn status(&self) -> crate::Result<Status> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
    }

    pub fn authenticate(&self, _reason: String, _options: AuthOptions) -> crate::Result<()> {
        Err(crate::Error::from(std::io::Error::other(
            "Biometry is not supported on desktop platforms",
        )))
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
