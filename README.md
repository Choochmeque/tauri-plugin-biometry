[![Crates.io](https://img.shields.io/crates/v/tauri-plugin-biometry)](https://crates.io/crates/tauri-plugin-biometry)
[![npm](https://img.shields.io/npm/v/@choochmeque/tauri-plugin-biometry-api)](https://www.npmjs.com/package/@choochmeque/tauri-plugin-biometry-api)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# Tauri Plugin Biometry

A Tauri plugin for biometric authentication (Touch ID, Face ID, fingerprint, etc.) on macOS, iOS, and Android.

## Features

- 🔐 Biometric authentication (Touch ID, Face ID, fingerprint)
- 📱 Support for iOS and Android
- 🖥️ Desktop support planned
- 🔑 Secure data storage with biometric protection
- 🎛️ Fallback to device passcode/password
- 🛡️ Native security best practices

## Installation

### Rust

Add the plugin to your `Cargo.toml`:

```toml
[dependencies]
tauri-plugin-biometry = "0.1"
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

Add the biometry permission to your `capabilities` in `default.json`:

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
console.log('Biometry type:', status.biometryType); // 0: None, 1: TouchID, 2: FaceID
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
    reason: 'Access your API key',
    cancelTitle: 'Cancel'
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
  Iris = 3
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

### Desktop
- Currently returns an error indicating biometry is not supported
- Desktop support may be added in future versions

## Error Codes

Common error codes returned by the plugin:

- `userCancel` - User cancelled the authentication
- `authenticationFailed` - Authentication failed (wrong biometric)
- `biometryNotAvailable` - Biometry is not available on device
- `biometryNotEnrolled` - No biometric data is enrolled
- `biometryLockout` - Too many failed attempts, biometry is locked

## Security Considerations

- All secure data is stored in the system keychain (iOS) or Android Keystore
- Data is encrypted and can only be accessed after successful biometric authentication
- The plugin follows platform-specific security best practices
- Consider implementing additional application-level encryption for highly sensitive data

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Acknowledgments

Built with [Tauri](https://tauri.app/) - Build smaller, faster, and more secure desktop applications with a web frontend.
