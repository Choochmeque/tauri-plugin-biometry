[![Crates.io](https://img.shields.io/crates/v/tauri-plugin-biometry)](https://crates.io/crates/tauri-plugin-biometry)
[![npm](https://img.shields.io/npm/v/@choochmeque/tauri-plugin-biometry-api)](https://www.npmjs.com/package/@choochmeque/tauri-plugin-biometry-api)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# Tauri Plugin Biometry

A Tauri plugin for biometric authentication (Touch ID, Face ID, Windows Hello, fingerprint, etc.) with support for macOS, Windows, iOS, and Android.

## Features

- 🔐 Biometric authentication (Touch ID, Face ID, Windows Hello, fingerprint)
- 📱 Full support for iOS and Android
- 🖥️ Desktop support for macOS (Touch ID) and Windows (Windows Hello)
- 🔑 Secure data storage with biometric protection (Android/iOS/macOS/Windows)
- 🎛️ Fallback to device passcode/password
- 🛡️ Native security best practices
- ⚡ Proper error handling with detailed error codes

## Installation

### Rust

Add the plugin to your `Cargo.toml`:

```toml
[dependencies]
tauri-plugin-biometry = "0.2"
```

### JavaScript/TypeScript

Install the JavaScript/TypeScript API:

```bash
npm install @choochmeque/tauri-plugin-biometry-api
# or
yarn add @choochmeque/tauri-plugin-biometry-api
# or
pnpm add @choochmeque/tauri-plugin-biometry-api
```

## Setup

### Rust Setup

Register the plugin in your Tauri app:

```rust
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_biometry::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### iOS Setup

Add `NSFaceIDUsageDescription` to your `Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>This app uses Face ID to secure your data</string>
```

### Android Setup

The plugin automatically handles the necessary permissions for Android.

### Permissions

The plugin uses Tauri's permission system with a two-tier model:

- `biometry:default` grants only the non-storage commands (`status` and `authenticate`).
- The storage commands (`has_data`, `get_data`, `set_data`, `remove_data`) must be granted explicitly per capability **and** scoped to the `(domain, name)` pairs the calling webview is allowed to touch. An empty scope rejects every call by design.

Minimal capability that only needs `status` / `authenticate`:

```json
{
  "identifier": "default",
  "windows": ["main"],
  "permissions": ["core:default", "biometry:default"]
}
```

Capability that also reads/writes a single domain:

```json
{
  "identifier": "default",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "biometry:default",
    {
      "identifier": "biometry:allow-has-data",
      "allow": [{ "domain": "com.myapp.creds" }]
    },
    {
      "identifier": "biometry:allow-get-data",
      "allow": [{ "domain": "com.myapp.creds" }]
    },
    {
      "identifier": "biometry:allow-set-data",
      "allow": [{ "domain": "com.myapp.creds" }]
    },
    {
      "identifier": "biometry:allow-remove-data",
      "allow": [{ "domain": "com.myapp.creds" }]
    }
  ]
}
```

Scope entry shape:

- `{ "domain": "com.example" }` — matches every `name` in that domain.
- `{ "domain": "com.example", "name": "session-token" }` — exact match on `(domain, name)`.
- Each storage permission also supports a `deny` array using the same shape. `deny` is evaluated before `allow`.

## Usage

### Check Biometry Status

```typescript
import { checkStatus } from '@choochmeque/tauri-plugin-biometry-api';

const status = await checkStatus();
console.log('Biometry available:', status.isAvailable);
console.log('Biometry type:', status.biometryType); // 0: None, 1: TouchID, 2: FaceID, 3: Iris, 4: Auto (Windows Hello)

if (status.error) {
  console.error('Error:', status.error);
  console.error('Error code:', status.errorCode);
}
```

### Authenticate

```typescript
import { authenticate } from '@choochmeque/tauri-plugin-biometry-api';

try {
  await authenticate('Please authenticate to continue', {
    allowDeviceCredential: true,
    cancelTitle: 'Cancel',
    fallbackTitle: 'Use Passcode',
    title: 'Authentication Required',
    subtitle: 'Access your secure data',
    confirmationRequired: false
  });
  console.log('Authentication successful');
} catch (error) {
  console.error('Authentication failed:', error);
}
```

### Store Secure Data

```typescript
import { setData, getData, hasData, removeData } from '@choochmeque/tauri-plugin-biometry-api';

// Store data with biometric protection
await setData({
  domain: 'com.myapp',
  name: 'api_key',
  data: 'secret-api-key-123'
});

// Check if data exists
const exists = await hasData({
  domain: 'com.myapp',
  name: 'api_key'
});

// Retrieve data (will prompt for biometric authentication)
if (exists) {
  const response = await getData({
    domain: 'com.myapp',
    name: 'api_key',
    reason: 'Access your API key'
  });
  console.log('Retrieved data:', response.data);
}

// Remove data
await removeData({
  domain: 'com.myapp',
  name: 'api_key'
});
```

## API Reference

### Types

```typescript
enum BiometryType {
  None = 0,
  TouchID = 1,
  FaceID = 2,
  Iris = 3,
  Auto = 4  // Windows Hello (auto-detects available biometry)
}

interface Status {
  isAvailable: boolean;
  biometryType: BiometryType;
  error?: string;
  errorCode?: string;
}

interface AuthOptions {
  allowDeviceCredential?: boolean;  // Allow fallback to device passcode
  cancelTitle?: string;              // iOS/Android: Cancel button text
  fallbackTitle?: string;            // iOS only: Fallback button text
  title?: string;                    // Android only: Dialog title
  subtitle?: string;                 // Android only: Dialog subtitle
  confirmationRequired?: boolean;    // Android only: Require explicit confirmation
}
```

### Functions

#### `checkStatus(): Promise<Status>`

Checks if biometric authentication is available on the device.

#### `authenticate(reason: string, options?: AuthOptions): Promise<void>`

Prompts the user for biometric authentication.

#### `hasData(options: DataOptions): Promise<boolean>`

Checks if secure data exists for the given domain and name.

#### `getData(options: GetDataOptions): Promise<DataResponse>`

Retrieves secure data after biometric authentication.

#### `setData(options: SetDataOptions): Promise<void>`

Stores data with biometric protection.

#### `removeData(options: RemoveDataOptions): Promise<void>`

Removes secure data.

## Platform Differences

### iOS

- Supports Touch ID and Face ID
- Requires `NSFaceIDUsageDescription` in Info.plist for Face ID
- Fallback button can be customized with `fallbackTitle`

### Android

- Supports fingerprint, face, and iris recognition.
- Dialog appearance can be customized with `title` and `subtitle`, and `confirmationRequired` enforces explicit confirmation.
- Storage is per-`(domain, name)`: a fresh AES-256 key encrypts the payload with AES-GCM and a random 12-byte IV, and that AES key is wrapped with a per-record 4096-bit RSA keypair held in AndroidKeyStore using OAEP with SHA-256 as the OAEP digest and SHA-1 as the MGF1 digest (the SHA-1 MGF1 matches AndroidKeyStore's internal default; SHA-256 is what protects the OAEP construction). The RSA key is auth-bound (`setUserAuthenticationRequired(true)`) and `setInvalidatedByBiometricEnrollment(true)`, so changing the enrolled biometric invalidates the record.
- The Keystore alias is `biometry_` + SHA-256 hex of `len(domain):domain:name`, so different `(domain, name)` records never share a keystore entry and same-named records under different domains never collide.
- AES-GCM AAD binds each ciphertext to `(version, algorithm-id, domain, name)`, so a stored blob cannot be replayed under a different `(domain, name)` or after a future algorithm change.
- Encrypted blobs and wrapped keys live in a Preferences DataStore that is excluded from both cloud backups (`dataExtractionRules`) and device-to-device transfers.
- `domain` and `name` are validated on every call: non-empty, `domain` ≤ 64 chars and matching `[A-Za-z0-9._-]`, `name` ≤ 256 chars.

### macOS

- Supports Touch ID
- Full keychain integration for secure data storage
- Same API as iOS for consistency
- Requires user authentication for data access
- **Important:** The app must be properly code-signed to use keychain data storage. Without proper signing, data storage operations may fail with errors

### Windows

- Supports Windows Hello (fingerprint, face, PIN). Returns `BiometryType.Auto` because Hello picks the modality.
- Storage uses the platform WebAuthn API (`webauthn.dll`) with the `hmac-secret` / PRF extension as the key-derivation source. A Hello-bound credential is enrolled per `(app-identifier, domain)`; the 32-byte PRF output is used directly as the AES-256-GCM key (it's HMAC-SHA-256 output, already a uniform 256-bit secret, so a KDF on top would be redundant). Per-record uniqueness comes from a fresh 32-byte random salt (the PRF input) and a fresh 12-byte random IV stored alongside the ciphertext.
- AES-GCM AAD binds each ciphertext to `(version, domain, name, salt, credential_id)`, so a stored blob cannot be replayed under a different `name`/`domain` in the vault.
- `authenticate` parents the Hello dialog to the calling Tauri window via `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`, so the prompt always renders on top.
- **Requirements:** Windows 11 with WebAuthn API ≥ v8 (needed for create-time PRF eval) and a user-verifying platform authenticator. `checkStatus()` probes both before reporting `isAvailable`.
- **First setData per `(app-identifier, domain)`** shows Windows' "Save your passkey" consent dialog once — that's the platform credential being enrolled. Subsequent `setData`/`getData` on the same domain only show the biometric/PIN prompt.
- `removeData` deletes the underlying WebAuthn credential when the last `name` in a domain is removed, so the passkey list stays clean.

## Error Codes

Common error codes returned by the plugin:

- `userCancel` - User cancelled the authentication
- `authenticationFailed` - Authentication failed (wrong biometric)
- `biometryNotAvailable` - Biometry is not available on device
- `biometryNotEnrolled` - No biometric data is enrolled
- `biometryLockout` - Too many failed attempts, biometry is locked
- `systemCancel` - System cancelled the operation (device busy)
- `appCancel` - Application cancelled the operation
- `invalidContext` - Invalid authentication context
- `notInteractive` - Non-interactive authentication not allowed
- `passcodeNotSet` - Device passcode not set
- `userFallback` - User chose to use fallback authentication
- `itemNotFound` - Keychain item not found (macOS/iOS)
- `authenticationRequired` - Authentication required but UI interaction not allowed
- `keychainError` - Generic keychain operation error
- `internalError` - Internal plugin error
- `notSupported` - Operation not supported on this platform
- `scopeDenied` - The requested `(domain, name)` is not in the capability's `allow` list (or is in `deny`)
- `dataNeedsReenrollment` - Stored Windows blob is from a previous plugin version and must be removed before re-storing

## Security Considerations

- All secure data is stored in the system keychain (macOS/iOS), Android Keystore, or Windows Credential Manager
- Data is encrypted and can only be accessed after successful biometric authentication
- The plugin follows platform-specific security best practices
- Windows uses AES-256-GCM with the key derived from the Windows Hello credential's WebAuthn `hmac-secret` / PRF output; the ciphertext is bound to `(version, domain, name, salt, credential_id)` via AES-GCM AAD
- Android uses AES-256-GCM with a fresh per-record AES key wrapped by a per-record AndroidKeyStore RSA-4096 key using OAEP (SHA-256 digest, MGF1 SHA-1 — matching AndroidKeyStore's internal MGF1); the wrapping key is auth-bound and biometric-enrollment-invalidated; the ciphertext is bound to `(version, algorithm-id, domain, name)` via AES-GCM AAD, and the DataStore file is excluded from cloud backups and device transfers
- Permission scoping (see *Permissions* above) is the primary authorization boundary — only the `(domain, name)` pairs declared in a capability's `allow` array are reachable from that webview, even if `biometry:allow-get-data` etc. is granted
- **macOS Code Signing:** Your app must be properly code-signed to use keychain storage on macOS. Development builds may work with ad-hoc signing, but production apps require valid Developer ID or App Store signing
- Consider implementing additional application-level encryption for highly sensitive data

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Acknowledgments

Built with [Tauri](https://tauri.app/) - Build smaller, faster
and more secure desktop applications with a web frontend.
