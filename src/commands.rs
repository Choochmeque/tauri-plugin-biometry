use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::{BiometryExt, Result};

#[command]
pub(crate) async fn status<R: Runtime>(app: AppHandle<R>) -> Result<Status> {
    app.biometry().status()
}

#[command]
pub(crate) async fn authenticate<R: Runtime>(
    reason: String,
    options: AuthOptions,
    app: AppHandle<R>,
) -> Result<()> {
    app.biometry().authenticate(reason, options)
}

#[command]
pub(crate) async fn has_data<R: Runtime>(options: DataOptions, app: AppHandle<R>) -> Result<bool> {
    app.biometry().has_data(options)
}

#[command]
pub(crate) async fn get_data<R: Runtime>(
    options: GetDataOptions,
    app: AppHandle<R>,
) -> Result<DataResponse> {
    app.biometry().get_data(options)
}

#[command]
pub(crate) async fn set_data<R: Runtime>(options: SetDataOptions, app: AppHandle<R>) -> Result<()> {
    app.biometry().set_data(options)
}

#[command]
pub(crate) async fn remove_data<R: Runtime>(
    options: RemoveDataOptions,
    app: AppHandle<R>,
) -> Result<()> {
    app.biometry().remove_data(options)
}
