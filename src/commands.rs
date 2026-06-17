use tauri::{command, AppHandle, Runtime, WebviewWindow};

use crate::models::{
    AuthOptions, DataOptions, DataResponse, GetDataOptions, RemoveDataOptions, SetDataOptions,
    Status,
};
use crate::{BiometryExt, Result};

#[command]
pub async fn status<R: Runtime>(app: AppHandle<R>) -> Result<Status> {
    app.biometry().status()
}

#[command]
pub async fn authenticate<R: Runtime>(
    reason: String,
    options: AuthOptions,
    app: AppHandle<R>,
) -> Result<()> {
    app.biometry().authenticate(reason, options)
}

#[command]
pub async fn has_data<R: Runtime>(options: DataOptions, app: AppHandle<R>) -> Result<bool> {
    app.biometry().has_data(options)
}

#[command]
pub async fn get_data<R: Runtime>(
    options: GetDataOptions,
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<DataResponse> {
    app.biometry().get_data(window, options)
}

#[command]
pub async fn set_data<R: Runtime>(
    options: SetDataOptions,
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Result<()> {
    app.biometry().set_data(window, options)
}

#[command]
pub async fn remove_data<R: Runtime>(options: RemoveDataOptions, app: AppHandle<R>) -> Result<()> {
    app.biometry().remove_data(options)
}
