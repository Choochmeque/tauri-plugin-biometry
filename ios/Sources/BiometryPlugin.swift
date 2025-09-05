
import LocalAuthentication
import SwiftRs
import Tauri
import UIKit
import WebKit

class BiometryStatus {
  let available: Bool
  let biometryType: LABiometryType
  let errorReason: String?
  let errorCode: String?

  init(available: Bool, biometryType: LABiometryType, errorReason: String?, errorCode: String?) {
    self.available = available
    self.biometryType = biometryType
    self.errorReason = errorReason
    self.errorCode = errorCode
  }
}

struct AuthOptions: Decodable {
  let reason: String
  var allowDeviceCredential: Bool?
  var fallbackTitle: String?
  var cancelTitle: String?
}

struct DataOptions: Decodable {
  let domain: String
  let name: String
}

struct SetDataOptions: Decodable {
  let domain: String
  let name: String
  let data: String
}

struct GetDataOptions: Decodable {
  let domain: String
  let name: String
  let reason: String
}

class BiometryPlugin: Plugin {
  let authenticationErrorCodeMap: [Int: String] = [
    0: "",
    LAError.appCancel.rawValue: "appCancel",
    LAError.authenticationFailed.rawValue: "authenticationFailed",
    LAError.invalidContext.rawValue: "invalidContext",
    LAError.notInteractive.rawValue: "notInteractive",
    LAError.passcodeNotSet.rawValue: "passcodeNotSet",
    LAError.systemCancel.rawValue: "systemCancel",
    LAError.userCancel.rawValue: "userCancel",
    LAError.userFallback.rawValue: "userFallback",
    LAError.biometryLockout.rawValue: "biometryLockout",
    LAError.biometryNotAvailable.rawValue: "biometryNotAvailable",
    LAError.biometryNotEnrolled.rawValue: "biometryNotEnrolled",
  ]

  var status: BiometryStatus!

  public override func load(webview: WKWebView) {
    let context = LAContext()
    var error: NSError?
    var available = context.canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics, error: &error)
    var reason: String? = nil
    var errorCode: String? = nil

    if available && context.biometryType == .faceID {
      let entry = Bundle.main.infoDictionary?["NSFaceIDUsageDescription"] as? String

      if entry == nil || entry?.count == 0 {
        available = false
        reason = "NSFaceIDUsageDescription is not in the app Info.plist"
        errorCode = authenticationErrorCodeMap[LAError.biometryNotAvailable.rawValue] ?? ""
      }
    } else if !available, let error = error {
      reason = error.localizedDescription
      if let failureReason = error.localizedFailureReason {
        reason = "\(reason ?? ""): \(failureReason)"
      }
      errorCode =
        authenticationErrorCodeMap[error.code] ?? authenticationErrorCodeMap[
          LAError.biometryNotAvailable.rawValue] ?? ""
    }

    self.status = BiometryStatus(
      available: available,
      biometryType: context.biometryType,
      errorReason: reason,
      errorCode: errorCode
    )
  }

  @objc func status(_ invoke: Invoke) {
    if self.status.available {
      invoke.resolve([
        "isAvailable": self.status.available,
        "biometryType": self.status.biometryType.rawValue,
      ])
    } else {
      invoke.resolve([
        "isAvailable": self.status.available,
        "biometryType": self.status.biometryType.rawValue,
        "error": self.status.errorReason ?? "",
        "errorCode": self.status.errorCode ?? "",
      ])
    }
  }
  
  @objc func authenticate(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(AuthOptions.self)

    let allowDeviceCredential = args.allowDeviceCredential ?? false

    guard self.status.available || allowDeviceCredential else {
      // Biometry unavailable, fallback disabled
      invoke.reject(
        self.status.errorReason ?? "",
        code: self.status.errorCode ?? ""
      )
      return
    }

    let context = LAContext()
    context.localizedFallbackTitle = args.fallbackTitle
    context.localizedCancelTitle = args.cancelTitle
    context.touchIDAuthenticationAllowableReuseDuration = 0

    // force system default fallback title if an empty string is provided (the OS hides the fallback button in this case)
    if allowDeviceCredential,
      let fallbackTitle = context.localizedFallbackTitle,
      fallbackTitle.isEmpty
    {
      context.localizedFallbackTitle = nil
    }

    context.evaluatePolicy(
      allowDeviceCredential
        ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: args.reason
    ) { success, error in
      if success {
        invoke.resolve()
      } else {
        if let policyError = error as? LAError {
          let code = self.authenticationErrorCodeMap[policyError.code.rawValue]
          invoke.reject(policyError.localizedDescription, code: code)
        } else {
          invoke.reject(
            "Unknown error",
            code: self.authenticationErrorCodeMap[LAError.authenticationFailed.rawValue]
          )
        }
      }
    }
  }

  @objc func hasData(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(DataOptions.self)
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecMatchLimit as String: kSecMatchLimitOne,
      kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
      kSecAttrAccount as String: args.name,
      kSecAttrService as String: args.domain
    ]
    
    var dataTypeRef: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
    
    if status != errSecSuccess && status != errSecInteractionNotAllowed {
        Logger.debug("hasData Error: \(status)")
    }
    
    let exists = (status == errSecSuccess) || (status == errSecInteractionNotAllowed)
    invoke.resolve(["hasData": exists])
  }
  
  @objc func setData(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(SetDataOptions.self)
    
    guard let valueData = args.data.data(using: .utf8) else {
      invoke.reject("Invalid data encoding")
      return
    }

    var flags: SecAccessControlCreateFlags = .userPresence
    
    guard let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      flags,
      nil
    ) else {
      invoke.reject("Error creating access control")
      return
    }
    
    let attributes: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: args.name,
      kSecValueData as String: valueData,
      kSecAttrService as String: args.domain,
      kSecAttrAccessControl as String: accessControl
    ]
    
    var status = SecItemAdd(attributes as CFDictionary, nil)
    
    if status == errSecDuplicateItem {
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: args.name,
        kSecAttrService as String: args.domain
      ]
      let updateAttributes: [String: Any] = [
        kSecValueData as String: valueData,
        kSecAttrAccessControl as String: accessControl
      ]
      status = SecItemUpdate(query as CFDictionary, updateAttributes as CFDictionary)
      
      if status != errSecSuccess {
        invoke.reject("Error updating item in keychain: \(status)")
        return
      }
    } else if status != errSecSuccess {
      invoke.reject("Error adding item to keychain: \(status)")
      return
    }
    
    invoke.resolve()
  }
  
  @objc func getData(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(GetDataOptions.self)
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecMatchLimit as String: kSecMatchLimitOne,
      kSecReturnData as String: kCFBooleanTrue!,
      kSecAttrAccount as String: args.name,
      kSecAttrService as String: args.domain,
      kSecUseOperationPrompt as String: args.reason
    ]
    
    DispatchQueue.global(qos: .userInitiated).async {
      var dataTypeRef: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
      
      DispatchQueue.main.async {
        if status == errSecSuccess, let data = dataTypeRef as? Data {
          if let string = String(data: data, encoding: .utf8) {
              invoke.resolve(["domain": args.domain, "name": args.name, "data": string])
          } else {
              invoke.reject("Failed to decode UTF-8 string")
          }
        } else {
          if status == errSecUserCanceled {
            invoke.reject("User canceled", code: "userCancel")
          } else {
            invoke.reject("Error retrieving item from keychain: \(status)")
          }
        }
      }
    }
  }
  
  @objc func removeData(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(DataOptions.self)
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: args.name,
      kSecAttrService as String: args.domain
    ]
    
    DispatchQueue.global(qos: .userInitiated).async {
      let status = SecItemDelete(query as CFDictionary)
      
      DispatchQueue.main.async {
        let success = (status == errSecSuccess) || (status == errSecItemNotFound)
        if success {
          invoke.resolve()
        } else {
          invoke.reject("Error deleting item from keychain: \(status)")
        }
      }
    }
  }
}

@_cdecl("init_plugin_biometry")
func initPlugin() -> Plugin {
  return BiometryPlugin()
}
