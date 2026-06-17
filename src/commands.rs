use tauri::{command, ipc::CommandScope, AppHandle, Runtime, WebviewWindow};

use crate::models::{
    AuthOptions, DataOptions, DataResponse, GetDataOptions, RemoveDataOptions, SetDataOptions,
    Status,
};
use crate::scope::{self, Entry as ScopeEntry};
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
    window: WebviewWindow<R>,
) -> Result<()> {
    app.biometry().authenticate(window, reason, options)
}

#[command]
pub async fn has_data<R: Runtime>(
    options: DataOptions,
    app: AppHandle<R>,
    command_scope: CommandScope<ScopeEntry>,
) -> Result<bool> {
    scope::check(&command_scope, &options.domain, &options.name)?;
    app.biometry().has_data(options)
}

#[command]
pub async fn get_data<R: Runtime>(
    options: GetDataOptions,
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    command_scope: CommandScope<ScopeEntry>,
) -> Result<DataResponse> {
    scope::check(&command_scope, &options.domain, &options.name)?;
    app.biometry().get_data(window, options)
}

#[command]
pub async fn set_data<R: Runtime>(
    options: SetDataOptions,
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    command_scope: CommandScope<ScopeEntry>,
) -> Result<()> {
    scope::check(&command_scope, &options.domain, &options.name)?;
    app.biometry().set_data(window, options)
}

#[command]
pub async fn remove_data<R: Runtime>(
    options: RemoveDataOptions,
    app: AppHandle<R>,
    command_scope: CommandScope<ScopeEntry>,
) -> Result<()> {
    scope::check(&command_scope, &options.domain, &options.name)?;
    app.biometry().remove_data(options)
}
