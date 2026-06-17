const COMMANDS: &[&str] = &[
    "authenticate",
    "status",
    "has_data",
    "get_data",
    "set_data",
    "remove_data",
];

fn main() {
    let result = tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .try_build();

    // when building documentation for Android the plugin build result is always Err() and is irrelevant to the crate documentation build
    let target = std::env::var("TARGET").expect("TARGET env var must be set by Cargo");
    if !(cfg!(docsrs) && target.contains("android")) {
        result.expect("tauri_plugin build failed");
    }
}
