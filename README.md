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

Configure the plugin permissions in your `capabilities/default.json`:

```json
{
  "permissions": {
    ["biometry:default"]
  }
}
```

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

- Supports fingerprint, face, and iris recognition
- Dialog appearance can be customized with `title` and `subtitle`
- Supports `confirmationRequired` for additional security

### macOS

- Supports Touch ID
- Full keychain integration for secure data storage
- Same API as iOS for consistency
- Requires user authentication for data access
- **Important:** The app must be properly code-signed to use keychain data storage. Without proper signing, data storage operations may fail with errors

### Windows

- Supports Windows Hello (fingerprint, face, PIN)
- Full secure data storage using Windows Hello credentials
- Data is encrypted using AES-256 with Windows Hello protected keys
- **Note:** `setData` will prompt for Windows Hello authentication when storing data
- Automatically focuses Windows Hello dialog
- Returns `BiometryType.Auto` as it uses Windows Hello's automatic selection

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

## Security Considerations

- All secure data is stored in the system keychain (macOS/iOS), Android Keystore, or Windows Credential Manager
- Data is encrypted and can only be accessed after successful biometric authentication
- The plugin follows platform-specific security best practices
- Windows uses AES-256 encryption with keys derived from Windows Hello credentials
- **macOS Code Signing:** Your app must be properly code-signed to use keychain storage on macOS. Development builds may work with ad-hoc signing, but production apps require valid Developer ID or App Store signing
- Consider implementing additional application-level encryption for highly sensitive data

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Acknowledgments

Built with [Tauri](https://tauri.app/) - Build smaller, faster
and more secure desktop applications with a web frontend.
