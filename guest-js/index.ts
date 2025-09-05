import { invoke } from "@tauri-apps/api/core";

/**
 * Enum representing the types of biometric authentication available on the device.
 * @enum {number}
 */
export enum BiometryType {
  /** No biometry available */
  None = 0,
  /** Apple Touch ID or Android fingerprint authentication */
  TouchID = 1,
  /** Apple Face ID or Android face authentication */
  FaceID = 2,
  /** Android iris authentication (Samsung devices) */
  Iris = 3,
}

/**
 * Status information about biometric authentication availability on the device.
 */
export interface Status {
  /** Whether biometric authentication is available on the device */
  isAvailable: boolean;
  /** The type of biometry available on the device */
  biometryType: BiometryType;
  /** Error message if biometry is not available */
  error?: string;
  /** Specific error code for debugging purposes */
  errorCode?:
    | "appCancel"
    | "authenticationFailed"
    | "invalidContext"
    | "notInteractive"
    | "passcodeNotSet"
    | "systemCancel"
    | "userCancel"
    | "userFallback"
    | "biometryLockout"
    | "biometryNotAvailable"
    | "biometryNotEnrolled";
}

/**
 * Options for configuring biometric authentication prompts.
 */
export interface AuthOptions {
  /**
   * Allow fallback to device passcode/password if biometry fails.
   * Available on both iOS and Android.
   * @default false
   */
  allowDeviceCredential?: boolean;

  /**
   * Text for the cancel button.
   * Available on both iOS and Android.
   * @default "Cancel"
   */
  cancelTitle?: string;

  /**
   * Text for the fallback button when biometry fails.
   * iOS only.
   * @default System default
   */
  fallbackTitle?: string;

  /**
   * Title of the authentication dialog.
   * Android only.
   * @default System default
   */
  title?: string;

  /**
   * Subtitle of the authentication dialog.
   * Android only.
   */
  subtitle?: string;

  /**
   * Whether to require explicit user confirmation after successful biometric authentication.
   * Android only.
   * @default true
   */
  confirmationRequired?: boolean;
}

/**
 * Options for identifying stored secure data.
 */
export interface DataOptions {
  /**
   * The domain/namespace for the data.
   * Use reverse domain notation (e.g., "com.myapp").
   */
  domain: string;

  /**
   * The unique name/key for the data within the domain.
   */
  name: string;
}

/**
 * Response containing retrieved secure data.
 */
export interface DataResponse {
  /** The domain/namespace of the retrieved data */
  domain: string;

  /** The name/key of the retrieved data */
  name: string;

  /** The actual data content as a string */
  data: string;
}

/**
 * Options for retrieving secure data with biometric authentication.
 */
export interface GetDataOptions {
  /**
   * The domain/namespace for the data.
   * Use reverse domain notation (e.g., "com.myapp").
   */
  domain: string;

  /**
   * The unique name/key for the data within the domain.
   */
  name: string;

  /**
   * The reason for requesting authentication, shown to the user.
   * @example "Access your saved credentials"
   */
  reason: string;

  /**
   * Text for the cancel button in the authentication dialog.
   * @default "Cancel"
   */
  cancelTitle?: string;
}

/**
 * Options for storing secure data with biometric protection.
 */
export interface SetDataOptions {
  /**
   * The domain/namespace for the data.
   * Use reverse domain notation (e.g., "com.myapp").
   */
  domain: string;

  /**
   * The unique name/key for the data within the domain.
   */
  name: string;

  /**
   * The data to store as a string.
   * For complex data, use JSON.stringify().
   */
  data: string;
}

/**
 * Options for removing secure data.
 * Same as DataOptions - requires domain and name to identify the data.
 */
export type RemoveDataOptions = DataOptions;

/**
 * Checks the availability and type of biometric authentication on the device.
 *
 * @returns {Promise<Status>} A promise that resolves to a Status object containing:
 * - `isAvailable`: Whether biometry is available and configured
 * - `biometryType`: The type of biometry available (None, TouchID, FaceID, or Iris)
 * - `error`: Error message if biometry is not available
 * - `errorCode`: Specific error code for debugging
 *
 * @example
 * ```typescript
 * const status = await checkStatus();
 * if (status.isAvailable) {
 *   console.log(`Biometry type: ${BiometryType[status.biometryType]}`);
 * } else {
 *   console.log(`Biometry not available: ${status.error}`);
 * }
 * ```
 */
export async function checkStatus(): Promise<Status> {
  return await invoke("plugin:biometry|status");
}

/**
 * Prompts the user for biometric authentication using the system's native dialog.
 *
 * @param {string} reason - The reason for authentication, displayed to the user.
 *                          This should clearly explain why authentication is needed.
 * @param {AuthOptions} options - Configuration options for the authentication prompt.
 *
 * @returns {Promise<void>} A promise that resolves on successful authentication.
 *
 * @throws {Error} Throws an error if authentication fails or is cancelled.
 *                 Check the error message and code for specific failure reasons.
 *
 * @example
 * ```typescript
 * try {
 *   await authenticate('Access your secure notes', {
 *     allowDeviceCredential: true,
 *     cancelTitle: 'Cancel',
 *     fallbackTitle: 'Use Password',
 *     title: 'Authenticate',
 *     subtitle: 'Verify your identity',
 *     confirmationRequired: false
 *   });
 *   console.log('Authentication successful!');
 * } catch (error) {
 *   console.error('Authentication failed:', error);
 * }
 * ```
 */
export async function authenticate(
  reason: string,
  options: AuthOptions = {},
): Promise<void> {
  await invoke("plugin:biometry|authenticate", {
    reason: reason,
    options: options,
  });
}

/**
 * Checks if secure data exists for the specified domain and name.
 * This method does not trigger biometric authentication.
 *
 * @param {DataOptions} options - The domain and name identifying the data.
 *
 * @returns {Promise<boolean>} A promise that resolves to `true` if data exists,
 *                             `false` otherwise.
 *
 * @example
 * ```typescript
 * const exists = await hasData({
 *   domain: 'com.myapp',
 *   name: 'api_token'
 * });
 *
 * if (exists) {
 *   console.log('API token is stored');
 * }
 * ```
 */
export async function hasData(options: DataOptions): Promise<boolean> {
  return await invoke("plugin:biometry|has_data", { options });
}

/**
 * Retrieves secure data after biometric authentication.
 * This will prompt the user for authentication before returning the data.
 *
 * @param {GetDataOptions} options - Options including domain, name, authentication reason,
 *                                   and optional cancel button text.
 *
 * @returns {Promise<DataResponse>} A promise that resolves to an object containing
 *                                   the domain, name, and decrypted data.
 *
 * @throws {Error} Throws an error if authentication fails, is cancelled,
 *                 or if the data doesn't exist.
 *
 * @example
 * ```typescript
 * try {
 *   const response = await getData({
 *     domain: 'com.myapp',
 *     name: 'api_token',
 *     reason: 'Access your API credentials',
 *     cancelTitle: 'Cancel'
 *   });
 *   console.log('Retrieved token:', response.data);
 * } catch (error) {
 *   console.error('Failed to retrieve data:', error);
 * }
 * ```
 */
export async function getData(options: GetDataOptions): Promise<DataResponse> {
  return await invoke("plugin:biometry|get_data", { options });
}

/**
 * Stores data securely with biometric protection.
 * The data will be encrypted and can only be retrieved after successful
 * biometric authentication.
 *
 * @param {SetDataOptions} options - Options including domain, name, and the data to store.
 *
 * @returns {Promise<void>} A promise that resolves when the data is successfully stored.
 *
 * @throws {Error} Throws an error if storage fails.
 *
 * @example
 * ```typescript
 * // Store a simple string
 * await setData({
 *   domain: 'com.myapp',
 *   name: 'api_token',
 *   data: 'secret-token-123'
 * });
 *
 * // Store JSON data
 * const userData = { id: 123, email: 'user@example.com' };
 * await setData({
 *   domain: 'com.myapp',
 *   name: 'user_profile',
 *   data: JSON.stringify(userData)
 * });
 * ```
 */
export async function setData(options: SetDataOptions): Promise<void> {
  await invoke("plugin:biometry|set_data", { options });
}

/**
 * Removes secure data from storage.
 * This operation does not require biometric authentication.
 *
 * @param {RemoveDataOptions} options - The domain and name identifying the data to remove.
 *
 * @returns {Promise<void>} A promise that resolves when the data is successfully removed.
 *                          Also resolves successfully if the data doesn't exist.
 *
 * @example
 * ```typescript
 * await removeData({
 *   domain: 'com.myapp',
 *   name: 'api_token'
 * });
 * console.log('Token removed from secure storage');
 * ```
 */
export async function removeData(options: RemoveDataOptions): Promise<void> {
  await invoke("plugin:biometry|remove_data", { options });
}
