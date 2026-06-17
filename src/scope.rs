//! Command-scope allowlist for the storage commands (`has_data`, `get_data`,
//! `set_data`, `remove_data`).
//!
//! Each capability that grants one of these permissions can constrain the
//! `domain` / `name` pairs the granted webview is allowed to touch:
//!
//! ```json
//! {
//!   "identifier": "biometry:allow-get-data",
//!   "allow": [
//!     { "domain": "com.myapp.creds" },
//!     { "domain": "com.myapp.tokens", "name": "session-token" }
//!   ],
//!   "deny": [
//!     { "domain": "com.myapp.creds", "name": "master-key" }
//!   ]
//! }
//! ```
//!
//! Semantics:
//! - An entry with `name` omitted matches **any** name in that domain.
//! - `deny` is evaluated first and beats `allow`.
//! - An empty `allow` list rejects every call — apps must opt in to the
//!   domains they actually use. This is the intentional secure default.

use serde::{Deserialize, Serialize};
use tauri::ipc::CommandScope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Domain this entry matches.
    pub domain: String,
    /// Optional exact-match name. Omit to match every name in `domain`.
    #[serde(default)]
    pub name: Option<String>,
}

impl Entry {
    fn matches(&self, domain: &str, name: &str) -> bool {
        self.domain == domain && self.name.as_deref().map_or(true, |n| n == name)
    }
}

/// Checks `(domain, name)` against the scope merged into the calling
/// webview's capability set. Returns `Err` if denied or not explicitly
/// allowed.
pub fn check(scope: &CommandScope<Entry>, domain: &str, name: &str) -> crate::Result<()> {
    if scope.denies().iter().any(|e| e.matches(domain, name)) {
        return Err(reject(domain, name, "denied by capability scope"));
    }
    if scope.allows().iter().any(|e| e.matches(domain, name)) {
        return Ok(());
    }
    Err(reject(
        domain,
        name,
        "not in capability allow-list — declare the (domain, name) in the capability's `allow` array",
    ))
}

fn reject(domain: &str, name: &str, why: &str) -> crate::Error {
    // Cross-platform path: scope.rs is shared with mobile, where
    // `crate::error::PluginInvokeError` doesn't exist. The unified
    // `crate::Error::Io` variant works everywhere, and the `scopeDenied:`
    // prefix preserves the distinguishable error code in the message.
    crate::Error::Io(std::io::Error::other(format!(
        "scopeDenied: biometry ({domain}, {name}) {why}"
    )))
}
