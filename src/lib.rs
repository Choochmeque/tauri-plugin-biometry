use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(all(desktop, not(target_os = "windows")))]
mod desktop;
#[cfg(mobile)]
mod mobile;
#[cfg(target_os = "windows")]
mod windows;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(all(desktop, not(target_os = "windows")))]
use desktop::Biometry;
#[cfg(mobile)]
use mobile::Biometry;
#[cfg(target_os = "windows")]
use windows::Biometry;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`], [`tauri::WebviewWindow`], [`tauri::Webview`] and [`tauri::Window`] to access the biometry APIs.
pub trait BiometryExt<R: Runtime> {
    fn biometry(&self) -> &Biometry<R>;
}

impl<R: Runtime, T: Manager<R>> crate::BiometryExt<R> for T {
    fn biometry(&self) -> &Biometry<R> {
        self.state::<Biometry<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("biometry")
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::authenticate,
            commands::has_data,
            commands::get_data,
            commands::set_data,
            commands::remove_data,
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let biometry = mobile::init(app, api)?;
            #[cfg(all(desktop, not(target_os = "windows")))]
            let biometry = desktop::init(app, api)?;
            #[cfg(target_os = "windows")]
            let biometry = windows::init(app, api)?;
            app.manage(biometry);
            Ok(())
        })
        .build()
}
