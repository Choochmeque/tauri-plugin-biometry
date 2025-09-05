use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.tauri.biometry";

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_biometry);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<Biometry<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "BiometryPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_biometry)?;
    Ok(Biometry(handle))
}

/// Access to the biometry APIs.
pub struct Biometry<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Biometry<R> {
    pub fn status(&self) -> crate::Result<Status> {
        self.0.run_mobile_plugin("status", ()).map_err(Into::into)
    }

    pub fn authenticate(&self, reason: String, options: AuthOptions) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("authenticate", AuthenticatePayload { reason, options })
            .map_err(Into::into)
    }

    pub fn has_data(&self, options: DataOptions) -> crate::Result<bool> {
        self.0
            .run_mobile_plugin("hasData", options)
            .and_then(|result: HasDataResponse| Ok(result.has_data))
            .map_err(Into::into)
    }

    pub fn get_data(&self, options: GetDataOptions) -> crate::Result<DataResponse> {
        self.0
            .run_mobile_plugin("getData", options)
            .map_err(Into::into)
    }

    pub fn set_data(&self, options: SetDataOptions) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("setData", options)
            .map_err(Into::into)
    }

    pub fn remove_data(&self, options: RemoveDataOptions) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("removeData", options)
            .map_err(Into::into)
    }
}
