
package app.tauri.biometry

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.EnumMap
import java.util.HashMap
import kotlin.math.max
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import android.content.Context

enum class BiometryResultType {
    SUCCESS, FAILURE, ERROR
}

private const val MAX_ATTEMPTS = "maxAttemps"
private const val BIOMETRIC_FAILURE = "authenticationFailed"
private const val INVALID_CONTEXT_ERROR = "invalidContext"

@InvokeArg
class AuthOptions {
    lateinit var reason: String
    var allowDeviceCredential: Boolean = false
    var title: String? = null
    var subtitle: String? = null
    var cancelTitle: String? = null
    var confirmationRequired: Boolean? = null
    var maxAttemps: Int = 3
}

@InvokeArg
class DataOptions {
    lateinit var domain: String
    lateinit var name: String
}

@InvokeArg
class SetDataOptions {
    lateinit var domain: String
    lateinit var name: String
    lateinit var data: String
}

@InvokeArg
class GetDataOptions {
    lateinit var domain: String
    lateinit var name: String
    var title: String? = null
    var subtitle: String? = null
    lateinit var reason: String
    var cancelTitle: String? = null
}

@InvokeArg
class RemoveDataOptions {
    lateinit var name: String
    lateinit var domain: String
}

// Extension property to create DataStore instance
private val Context.biometricDataStore: DataStore<Preferences> by preferencesDataStore(name = "biometric_data")

@TauriPlugin
class BiometryPlugin(private val activity: Activity): Plugin(activity) {
    private var biometryTypes: ArrayList<BiometryType> = arrayListOf()
    private val dataStore: DataStore<Preferences> = activity.biometricDataStore
    private val coroutineScope = CoroutineScope(Dispatchers.IO)

    companion object {
        var RESULT_EXTRA_PREFIX = ""
        const val TITLE = "title"
        const val SUBTITLE = "subtitle"
        const val REASON = "reason"
        const val CANCEL_TITLE = "cancelTitle"
        const val RESULT_TYPE = "type"
        const val RESULT_ERROR_CODE = "errorCode"
        const val RESULT_ERROR_MESSAGE = "errorMessage"
        const val DEVICE_CREDENTIAL = "allowDeviceCredential"
        const val CONFIRMATION_REQUIRED = "confirmationRequired"
        
        private const val RSA_CIPHER_CONFIG = "RSA/ECB/PKCS1Padding"
        private const val AES_CIPHER_CONFIG = "AES/GCM/NoPadding"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_KEY_SIZE = 256
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128

        // Maps biometry error numbers to string error codes
        private var biometryErrorCodeMap: MutableMap<Int, String> = HashMap()
        private var biometryNameMap: MutableMap<BiometryType, String> = EnumMap(BiometryType::class.java)

       init {
           biometryErrorCodeMap[BiometricManager.BIOMETRIC_SUCCESS] = ""
           biometryErrorCodeMap[BiometricManager.BIOMETRIC_SUCCESS] = ""
           biometryErrorCodeMap[BiometricPrompt.ERROR_CANCELED] = "systemCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_HW_NOT_PRESENT] = "biometryNotAvailable"
           biometryErrorCodeMap[BiometricPrompt.ERROR_HW_UNAVAILABLE] = "biometryNotAvailable"
           biometryErrorCodeMap[BiometricPrompt.ERROR_LOCKOUT] = "biometryLockout"
           biometryErrorCodeMap[BiometricPrompt.ERROR_LOCKOUT_PERMANENT] = "biometryLockout"
           biometryErrorCodeMap[BiometricPrompt.ERROR_NEGATIVE_BUTTON] = "userCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_NO_BIOMETRICS] = "biometryNotEnrolled"
           biometryErrorCodeMap[BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL] = "noDeviceCredential"
           biometryErrorCodeMap[BiometricPrompt.ERROR_NO_SPACE] = "systemCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_TIMEOUT] = "systemCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_UNABLE_TO_PROCESS] = "systemCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_USER_CANCELED] = "userCancel"
           biometryErrorCodeMap[BiometricPrompt.ERROR_VENDOR] = "systemCancel"

           biometryNameMap[BiometryType.NONE] = "No Authentication"
           biometryNameMap[BiometryType.FINGERPRINT] = "Fingerprint Authentication"
           biometryNameMap[BiometryType.FACE] = "Face Authentication"
           biometryNameMap[BiometryType.IRIS] = "Iris Authentication"
       }
    }

    override fun load(webView: WebView) {
        super.load(webView)

        biometryTypes = ArrayList()
        val manager = activity.packageManager
        if (manager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            biometryTypes.add(BiometryType.FINGERPRINT)
        }
        if (manager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
            biometryTypes.add(BiometryType.FACE)
        }
        if (manager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
            biometryTypes.add(BiometryType.IRIS)
        }
        if (biometryTypes.size == 0) {
            biometryTypes.add(BiometryType.NONE)
        }
    }

    /**
     * Check the device's availability and type of biometric authentication.
     */
    @Command
    fun status(invoke: Invoke) {
        val manager = BiometricManager.from(activity)
        val biometryResult = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
        } else {
            @Suppress("DEPRECATION")
            manager.canAuthenticate()
        }
        val ret = JSObject()

        val available = biometryResult == BiometricManager.BIOMETRIC_SUCCESS
        ret.put(
            "isAvailable",
            available
        )

        ret.put("biometryType", biometryTypes[0].type)

        if (!available) {
            var reason = ""
            when (biometryResult) {
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> reason =
                    "Biometry unavailable."
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> reason =
                    "Biometrics not enrolled."
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> reason =
                    "No biometric on this device."
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> reason =
                    "A security update is required."
                BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> reason =
                    "Unsupported biometry."
                BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> reason =
                    "Unknown biometry state."
            }

            var errorCode = biometryErrorCodeMap[biometryResult]
            if (errorCode == null) {
                errorCode = "biometryNotAvailable"
            }
            ret.put("error", reason)
            ret.put("errorCode", errorCode)
        }

        invoke.resolve(ret)
    }

    /**
     * Prompt the user for biometric authentication.
     */
    @Command
    fun authenticate(invoke: Invoke) {
        // The result of an intent is supposed to have the package name as a prefix
        RESULT_EXTRA_PREFIX = activity.packageName + "."
        val intent = Intent(
            activity,
            BiometryActivity::class.java
        )
        
        val args = invoke.parseArgs(AuthOptions::class.java)

        // Pass the options to the activity
        intent.putExtra(
            TITLE,
            args.title ?: (biometryNameMap[biometryTypes[0]] ?: "")
        )
        intent.putExtra(SUBTITLE, args.subtitle)
        intent.putExtra(REASON, args.reason)
        intent.putExtra(CANCEL_TITLE, args.cancelTitle)
        intent.putExtra(DEVICE_CREDENTIAL, args.allowDeviceCredential)
        args.confirmationRequired?.let {
            intent.putExtra(CONFIRMATION_REQUIRED, it)
        }

        val maxAttemptsConfig = args.maxAttemps
        val maxAttempts = max(maxAttemptsConfig, 1)
        intent.putExtra(MAX_ATTEMPTS, maxAttempts)
        startActivityForResult(invoke, intent, "authenticateResult")
    }

    @ActivityCallback
    private fun authenticateResult(invoke: Invoke, result: ActivityResult) {
        val resultCode = result.resultCode

        // If the system canceled the activity, we might get RESULT_CANCELED in resultCode.
        // In that case return that immediately, because there won't be any data.
        if (resultCode == Activity.RESULT_CANCELED) {
            invoke.reject(
                "The system canceled authentication",
                biometryErrorCodeMap[BiometricPrompt.ERROR_CANCELED]
            )
            return
        }

        // Convert the string result type to an enum
        val data = result.data
        val resultTypeName = data?.getStringExtra(
            RESULT_EXTRA_PREFIX + RESULT_TYPE
        )
        if (resultTypeName == null) {
            invoke.reject(
                "Missing data in the result of the activity",
                INVALID_CONTEXT_ERROR
            )
            return
        }
        val resultType = try {
            BiometryResultType.valueOf(resultTypeName)
        } catch (e: IllegalArgumentException) {
            invoke.reject(
                "Invalid data in the result of the activity",
                INVALID_CONTEXT_ERROR
            )
            return
        }
        val errorCode = data.getIntExtra(
            RESULT_EXTRA_PREFIX + RESULT_ERROR_CODE,
            0
        )
        var errorMessage = data.getStringExtra(
            RESULT_EXTRA_PREFIX + RESULT_ERROR_MESSAGE
        )
        when (resultType) {
            BiometryResultType.SUCCESS -> invoke.resolve()
            BiometryResultType.FAILURE ->         // Biometry was successfully presented but was not recognized
                invoke.reject(errorMessage, BIOMETRIC_FAILURE)

            BiometryResultType.ERROR -> {
                // The user cancelled, the system cancelled, or some error occurred.
                // If the user cancelled, errorMessage is the text of the "negative" button,
                // which is not especially descriptive.
                if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    errorMessage = "Cancel button was pressed"
                }
                invoke.reject(errorMessage, biometryErrorCodeMap[errorCode])
            }
        }
    }

    internal enum class BiometryType(val type: Int) {
        NONE(0), FINGERPRINT(1), FACE(2), IRIS(3);
    }
    
    private fun generateKeyPair(keyName: String): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE
        )
        
        val builder = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(4096)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        
        keyPairGenerator.initialize(builder.build())
        
        return keyPairGenerator.generateKeyPair()
    }
    
    private fun getKeyPair(keyName: String): KeyPair? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        if (keyStore.containsAlias(keyName)) {
            // Get private key
            val privateKey = keyStore.getKey(keyName, null) as PrivateKey
            
            // Get public key
            val publicKey = keyStore.getCertificate(keyName).publicKey
            
            // Return a key pair
            return KeyPair(publicKey, privateKey)
        }
        return null
    }

    @Command
    fun hasData(invoke: Invoke) {
        val args = invoke.parseArgs(DataOptions::class.java)
        
        coroutineScope.launch {
            try {
                val key = stringPreferencesKey(args.name)
                val hasData = dataStore.data
                    .map { preferences -> preferences.contains(key) }
                    .first()
                
                val result = JSObject()
                result.put("hasData", hasData)
                invoke.resolve(result)
            } catch (e: Exception) {
                invoke.reject("Failed to check data: ${e.message}")
            }
        }
    }

    @Command
    fun setData(invoke: Invoke) {
        val args = invoke.parseArgs(SetDataOptions::class.java)
        
        coroutineScope.launch {
            try {
                val dataKey = stringPreferencesKey(args.name)
                val ivKey = stringPreferencesKey("${args.name}_iv")
                val aesKey = stringPreferencesKey("${args.name}_key")
                
                // Clear existing data
                dataStore.edit { preferences ->
                    preferences.remove(dataKey)
                    preferences.remove(ivKey)
                    preferences.remove(aesKey)
                }
                
                // Delete the key from keystore
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                keyStore.deleteEntry(args.domain)

                // Generate RSA key pair for encrypting AES key
                val keyPair = generateKeyPair(args.domain)
                
                // Generate AES key for data encryption
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
                keyGenerator.init(AES_KEY_SIZE)
                val secretKey = keyGenerator.generateKey()
                
                // Generate IV for AES-GCM
                val iv = ByteArray(GCM_IV_LENGTH)
                SecureRandom().nextBytes(iv)
                
                // Encrypt data with AES-GCM
                val aesCipher = Cipher.getInstance(AES_CIPHER_CONFIG)
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
                val encryptedData = aesCipher.doFinal(args.data.toByteArray())
                
                // Encrypt AES key with RSA
                val rsaCipher = Cipher.getInstance(RSA_CIPHER_CONFIG)
                rsaCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
                val encryptedAesKey = rsaCipher.doFinal(secretKey.encoded)
                
                // Store encrypted data, IV, and encrypted AES key
                dataStore.edit { preferences ->
                    preferences[dataKey] = Base64.encodeToString(encryptedData, Base64.DEFAULT)
                    preferences[ivKey] = Base64.encodeToString(iv, Base64.DEFAULT)
                    preferences[aesKey] = Base64.encodeToString(encryptedAesKey, Base64.DEFAULT)
                }
                
                invoke.resolve()
            } catch (e: Exception) {
                invoke.reject("Failed to set data: ${e.message}")
            }
        }
    }

    @Command
    fun getData(invoke: Invoke) {
        val args = invoke.parseArgs(GetDataOptions::class.java)
        
        try {
            val keyPair = getKeyPair(args.domain)
            if (keyPair == null) {
                invoke.reject("No key pair found")
                return
            }
            
            val rsaCipher = Cipher.getInstance(RSA_CIPHER_CONFIG)
            rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate())
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(args.title ?: (biometryNameMap[biometryTypes[0]] ?: ""))
                .setSubtitle(args.subtitle)
                .setDescription(args.reason)
                .setNegativeButtonText(args.cancelTitle ?: "cancelTitle")
                .build()
            
            val executor: Executor = ContextCompat.getMainExecutor(activity)
            
            val biometricPrompt = BiometricPrompt(
                activity as FragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        super.onAuthenticationSucceeded(result)
                        
                        coroutineScope.launch {
                            try {
                                val rsaCipher = result.cryptoObject?.cipher
                                    ?: throw Exception("Cipher is null")
                                
                                val dataKey = stringPreferencesKey(args.name)
                                val ivKey = stringPreferencesKey("${args.name}_iv")
                                val aesKeyKey = stringPreferencesKey("${args.name}_key")
                                
                                val preferences = dataStore.data.first()
                                val encryptedData = preferences[dataKey]
                                    ?: throw Exception("No data found")
                                val ivString = preferences[ivKey]
                                    ?: throw Exception("No IV found")
                                val encryptedAesKey = preferences[aesKeyKey]
                                    ?: throw Exception("No AES key found")
                                
                                // Decrypt AES key with RSA
                                val aesKeyBytes = rsaCipher.doFinal(
                                    Base64.decode(encryptedAesKey, Base64.DEFAULT)
                                )
                                val secretKey = SecretKeySpec(aesKeyBytes, "AES")
                                
                                // Decrypt data with AES-GCM
                                val iv = Base64.decode(ivString, Base64.DEFAULT)
                                val aesCipher = Cipher.getInstance(AES_CIPHER_CONFIG)
                                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                                aesCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
                                
                                val decryptedBytes = aesCipher.doFinal(
                                    Base64.decode(encryptedData, Base64.DEFAULT)
                                )
                                
                                val resultObject = JSObject()
                                resultObject.put("domain", args.domain)
                                resultObject.put("name", args.name)
                                resultObject.put("data", String(decryptedBytes))
                                invoke.resolve(resultObject)
                            } catch (e: BadPaddingException) {
                                invoke.reject("Decryption failed (BadPadding) - likely wrong key or cipher config")
                            } catch (e: IllegalBlockSizeException) {
                                invoke.reject("Decryption failed (IllegalBlockSize) - likely wrong key or cipher config")
                            } catch (e: Exception) {
                                invoke.reject("Failed to decrypt data: ${e.message}")
                            }
                        }
                    }
                    
                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        super.onAuthenticationError(errorCode, errString)
                        invoke.reject(errString.toString(), biometryErrorCodeMap[errorCode])
                    }
                    
                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        // Don't reject here, let the user retry
                    }
                }
            )
            
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(rsaCipher))
        } catch (e: Exception) {
            invoke.reject("Failed to get data: ${e.message}")
        }
    }

    @Command
    fun removeData(invoke: Invoke) {
        val args = invoke.parseArgs(RemoveDataOptions::class.java)
        
        coroutineScope.launch {
            try {
                val dataKey = stringPreferencesKey(args.name)
                val ivKey = stringPreferencesKey("${args.name}_iv")
                val aesKey = stringPreferencesKey("${args.name}_key")
                
                dataStore.edit { preferences ->
                    preferences.remove(dataKey)
                    preferences.remove(ivKey)
                    preferences.remove(aesKey)
                }
                
                // Delete the key from keystore
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                keyStore.deleteEntry(args.domain)
                
                invoke.resolve()
            } catch (e: Exception) {
                invoke.reject("Failed to remove data: ${e.message}")
            }
        }
    }
}
