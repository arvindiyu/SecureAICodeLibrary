# Secure Coding Prompt: Android Development (Java/Kotlin)

## Purpose

This prompt guides you in implementing secure coding practices for Android applications using Java or Kotlin. Use this prompt to generate code that follows Android security best practices and avoids common mobile application vulnerabilities.

## Secure Android Development Prompt

```
As a secure Android developer, help me implement [FEATURE/FUNCTIONALITY] with security as a priority. 

Consider these security aspects in your implementation:
1. Data storage security (EncryptedSharedPreferences, Room with encryption)
2. Network security (TLS, certificate pinning, network security config)
3. Authentication and authorization (secure token storage, biometric auth)
4. Input validation and sanitization
5. Protection against common mobile vulnerabilities (insecure data storage, insecure communication)
6. Privacy features (runtime permissions, data minimization)
7. Secure IPC mechanisms (Intents, ContentProviders)
8. Root detection implementation
9. Application signing and verification
10. Security event logging
11. Secure Kotlin/Java coding patterns
12. SafetyNet Attestation API usage
13. Protection against screen overlay attacks
14. Secure WebView implementation
15. Anti-tampering mechanisms

Technical requirements:
- Minimum API level: [API level]
- Language: [Java/Kotlin]
- Architecture: [MVVM, Clean Architecture, etc.]
- Authentication method: [biometric, OAuth, etc.]
- Data persistence requirements: [local, remote]
- Security compliance requirements: [OWASP MASVS level, PCI-DSS, HIPAA, etc.]

Follow these Android security best practices:
- Use EncryptedSharedPreferences or EncryptedFile for sensitive data
- Implement Network Security Config with proper TLS
- Use explicit intents for internal app communication
- Apply ContentProvider permissions appropriately
- Validate all user inputs and external data
- Implement proper error handling that doesn't leak sensitive information
- Use the Android Keystore System for cryptographic operations
- Implement certificate pinning for critical API endpoints
- Apply security-focused ProGuard rules for code obfuscation
- Follow secure coding patterns for concurrency and asynchronous operations
- Use StrictMode to detect accidental data leaks
```

## Security Considerations for Android Development

### Secure Data Storage

#### EncryptedSharedPreferences Example

```kotlin
// Import statements
import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * SecurePreferenceManager - A secure wrapper for SharedPreferences that encrypts all data
 * using EncryptedSharedPreferences from the Android Security library
 */
class SecurePreferenceManager(context: Context) {
    
    private val sharedPreferences by lazy {
        try {
            // Get or create master key for encryption
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
            
            // Initialize encrypted shared preferences
            EncryptedSharedPreferences.create(
                "secure_prefs",
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: GeneralSecurityException) {
            // Handle encryption errors securely
            logSecurityException("Error creating encrypted preferences: ${e.message}")
            null
        } catch (e: IOException) {
            // Handle I/O errors securely
            logSecurityException("I/O error creating encrypted preferences: ${e.message}")
            null
        }
    }
    
    /**
     * Securely store a string value
     * @param key The preference key
     * @param value The string value to store
     * @return true if successful, false otherwise
     */
    fun storeSecureString(key: String, value: String): Boolean {
        return try {
            sharedPreferences?.edit()?.putString(key, value)?.apply()
            true
        } catch (e: Exception) {
            logSecurityException("Failed to store secure string: ${e.message}")
            false
        }
    }
    
    /**
     * Retrieve a securely stored string value
     * @param key The preference key
     * @param defaultValue The default value if key not found
     * @return The stored string or defaultValue if not found
     */
    fun getSecureString(key: String, defaultValue: String): String {
        return try {
            sharedPreferences?.getString(key, defaultValue) ?: defaultValue
        } catch (e: Exception) {
            logSecurityException("Failed to retrieve secure string: ${e.message}")
            defaultValue
        }
    }
    
    /**
     * Remove a secure preference
     * @param key The preference key to remove
     */
    fun removeSecureValue(key: String) {
        try {
            sharedPreferences?.edit()?.remove(key)?.apply()
        } catch (e: Exception) {
            logSecurityException("Failed to remove secure value: ${e.message}")
        }
    }
    
    /**
     * Clear all secure preferences
     */
    fun clearAllSecureData() {
        try {
            sharedPreferences?.edit()?.clear()?.apply()
        } catch (e: Exception) {
            logSecurityException("Failed to clear secure preferences: ${e.message}")
        }
    }
    
    /**
     * Securely log security exceptions without exposing sensitive details
     */
    private fun logSecurityException(message: String) {
        // In production, use a secure logging mechanism that doesn't expose sensitive details
        // Log.e("SecurePrefs", "Security operation failed") // Minimal information in release builds
        
        // More detailed logging for debug builds only
        if (BuildConfig.DEBUG) {
            Log.d("SecurePrefs", message)
        }
    }
}
import androidx.security.crypto.MasterKey

// Create or retrieve the Master Key for encryption
val mainKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

// Create the EncryptedSharedPreferences
val securePreferences = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    mainKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Store sensitive data
securePreferences.edit().apply {
    putString("auth_token", "sensitive-token-value")
    putString("user_id", "user123")
    apply()
}

// Retrieve sensitive data
val authToken = securePreferences.getString("auth_token", null)
```

#### Room Database with SQLCipher

```kotlin
// build.gradle
dependencies {
    implementation "net.zetetic:android-database-sqlcipher:4.5.0"
    implementation "androidx.sqlite:sqlite-ktx:2.1.0"
}

// Database configuration
@Database(entities = [SecureData::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun secureDataDao(): SecureDataDao
    
    companion object {
        private var INSTANCE: AppDatabase? = null
        
        fun getDatabase(context: Context, passphrase: ByteArray): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "secure_database"
                )
                .openHelperFactory(SupportFactory(passphrase))
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}

// Generate secure passphrase
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()
    
val securePreferences = EncryptedSharedPreferences.create(
    context,
    "secure_db_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Store passphrase securely or derive it from user authentication
val passphraseKey = securePreferences.getString("db_passphrase", null)
    ?: generateAndStoreNewPassphrase(securePreferences)
    
val passphrase = SQLiteDatabase.getBytes(passphraseKey.toCharArray())
val database = AppDatabase.getDatabase(context, passphrase)
```

### Network Security

#### Network Security Config

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Use certificate pinning for specific domains -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">secure-api.example.com</domain>
        <pin-set expiration="2024-01-01">
            <!-- SHA-256 hash of the certificate's Subject Public Key Info, base64-encoded -->
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <!-- Backup pin -->
            <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
        </pin-set>
        <!-- Force TLS 1.2 or higher -->
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </domain-config>
    
    <!-- Default configuration for all other domains -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```kotlin
// In your app's manifest
<application
    ...
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

#### OkHttp with Certificate Pinning

```kotlin
// Import statements
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

// Create a certificate pinner with your domain and certificate hashes
val certificatePinner = CertificatePinner.Builder()
    .add("secure-api.example.com", 
         "sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=",
         "sha256/fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=")
    .build()

// Create a secure OkHttpClient
val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .followRedirects(false) // Prevent redirect attacks
    .followSslRedirects(false) // Prevent SSL redirect attacks
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS)) // Enforce modern TLS
    .build()

// Use the client for API calls
val request = Request.Builder()
    .url("https://secure-api.example.com/data")
    .header("Authorization", "Bearer $secureToken")
    .build()

client.newCall(request).execute().use { response ->
    if (response.isSuccessful) {
        val responseBody = response.body?.string()
        // Process the response
    } else {
        // Handle error securely
        Log.e("API", "Error code: ${response.code}")
    }
}
```

### Authentication & Authorization

#### Biometric Authentication

```kotlin
// Import statements
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class SecureActivity : FragmentActivity() {

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Create a biometric prompt
        val executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    // Handle authentication error
                    Log.e("Biometric", "Authentication error: $errorCode, $errString")
                    showFallbackAuthentication()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // Authentication succeeded, proceed with operation
                    val cryptoObject = result.cryptoObject
                    if (cryptoObject?.cipher != null) {
                        // Use the cipher for encryption/decryption
                        processWithSecureCipher(cryptoObject.cipher!!)
                    } else {
                        // Proceed with authenticated operation
                        proceedWithAuthenticatedOperation()
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Handle authentication failure
                    Log.e("Biometric", "Authentication failed")
                }
            })

        // Configure the biometric prompt
        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Cancel")
            .setConfirmationRequired(true)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
            
        // Check if biometric auth is available
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Biometric auth is available
                showBiometricPrompt()
            }
            else -> {
                // Biometric auth is not available, use fallback
                showFallbackAuthentication()
            }
        }
    }
    
    private fun showBiometricPrompt() {
        // Get the cipher for the crypto object
        val cipher = getCipher()
        val secretKeyName = "biometric_encryption_key"
        
        if (secretKeyExists(secretKeyName)) {
            // Key exists, initialize the cipher for decryption
            val secretKey = getKey(secretKeyName)
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
        } else {
            // Key doesn't exist, create a new key and initialize cipher for encryption
            val secretKey = createKey(secretKeyName)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        }
        
        // Show the biometric prompt
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
    
    // Create a key in the Android Keystore
    private fun createKey(keyName: String): SecretKey {
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    keyName,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                // Only allow the key to be used if authenticated within the last 30 seconds
                .setUserAuthenticationValidityDurationSeconds(30)
                .build()
            )
        }.generateKey()
    }
    
    // Check if key exists in Android Keystore
    private fun secretKeyExists(keyName: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.containsAlias(keyName)
    }
    
    // Get key from Android Keystore
    private fun getKey(keyName: String): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKeyEntry = keyStore.getEntry(keyName, null) as KeyStore.SecretKeyEntry
        return secretKeyEntry.secretKey
    }
    
    // Get a cipher instance
    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}"
        )
    }
}
```

### Secure IPC & Content Providers

#### Secure Intent Usage

```kotlin
// Explicit Intent - Preferred for internal app communication
val intent = Intent(context, SecureActivity::class.java)
intent.putExtra("non_sensitive_data", "data")
startActivity(intent)

// Secure broadcast with permissions
val secureAction = "com.example.app.SECURE_ACTION"
val intent = Intent(secureAction)
intent.setPackage("com.example.app") // Restrict to your app's package
context.sendBroadcast(intent, "com.example.app.CUSTOM_PERMISSION")

// In AndroidManifest.xml
<permission
    android:name="com.example.app.CUSTOM_PERMISSION"
    android:protectionLevel="signature" />
```

#### Secure Content Provider

```kotlin
// In AndroidManifest.xml
<provider
    android:name=".SecureContentProvider"
    android:authorities="com.example.app.provider"
    android:exported="false"
    android:grantUriPermissions="false"
    android:permission="com.example.app.PROVIDER_PERMISSION" />

// Content Provider implementation
class SecureContentProvider : ContentProvider() {
    
    // Uri matcher for routing queries
    private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH)
    private lateinit var dbHelper: SecureDbHelper
    
    companion object {
        private const val SECURE_DATA = 1
        private const val SECURE_DATA_ID = 2
        private const val AUTHORITY = "com.example.app.provider"
        
        // Define URIs
        val SECURE_DATA_URI = Uri.parse("content://$AUTHORITY/secure_data")
    }
    
    override fun onCreate(): Boolean {
        // Initialize the provider
        dbHelper = SecureDbHelper(context!!)
        
        // Set up URI routing
        uriMatcher.addURI(AUTHORITY, "secure_data", SECURE_DATA)
        uriMatcher.addURI(AUTHORITY, "secure_data/#", SECURE_DATA_ID)
        
        return true
    }
    
    override fun query(...): Cursor? {
        // Check permissions at runtime even though we've set them in the manifest
        context?.enforceCallingPermission("com.example.app.PROVIDER_PERMISSION", "Permission denied")
        
        // Validate input parameters
        if (!isValidProjection(projection)) {
            throw IllegalArgumentException("Invalid projection")
        }
        
        // Use parameterized queries to prevent SQL injection
        val db = dbHelper.readableDatabase
        val cursor: Cursor?
        
        when (uriMatcher.match(uri)) {
            SECURE_DATA -> {
                cursor = db.query(
                    "secure_data_table",
                    projection,
                    selection,
                    selectionArgs,
                    null,
                    null,
                    sortOrder
                )
            }
            SECURE_DATA_ID -> {
                val id = ContentUris.parseId(uri)
                cursor = db.query(
                    "secure_data_table",
                    projection,
                    "_id = ?",
                    arrayOf(id.toString()),
                    null,
                    null,
                    sortOrder
                )
            }
            else -> throw IllegalArgumentException("Unknown URI: $uri")
        }
        
        // Register for changes
        cursor?.setNotificationUri(context!!.contentResolver, uri)
        
        return cursor
    }
    
    // Validate projection to prevent leaking sensitive columns
    private fun isValidProjection(projection: Array<String>?): Boolean {
        if (projection == null) return true
        
        val validColumns = setOf("_id", "name", "public_data")
        return projection.all { it in validColumns }
    }
    
    // Implement other CRUD methods with similar security checks
}
```

### Root Detection & Tamper Protection

```kotlin
fun checkForRootedDevice(): Boolean {
    // Check for common su binaries
    val suPaths = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU"
    )
    
    for (path in suPaths) {
        if (File(path).exists()) {
            return true
        }
    }
    
    // Check for root management apps
    val rootApps = arrayOf(
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.topjohnwu.magisk"
    )
    
    val packageManager = context.packageManager
    for (rootApp in rootApps) {
        try {
            packageManager.getPackageInfo(rootApp, 0)
            return true
        } catch (e: PackageManager.NameNotFoundException) {
            // Package not found, continue checking
        }
    }
    
    // Check for RW access to system directories
    val systemPaths = arrayOf(
        "/system",
        "/system/bin",
        "/system/xbin",
        "/data"
    )
    
    for (path in systemPaths) {
        val file = File(path)
        if (file.exists() && file.canWrite()) {
            return true
        }
    }
    
    // Check if build tags indicate a dev build
    val buildTags = Build.TAGS
    if (buildTags != null && buildTags.contains("test-keys")) {
        return true
    }
    
    return false
}

fun verifyAppSignature(): Boolean {
    try {
        // Get the package info with signatures
        val packageInfo = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNATURES
        )
        
        // Calculate the expected signature hash
        val expectedSignatureHash = "your-app-signature-hash-here"
        
        // Get the actual signature and hash it
        for (signature in packageInfo.signatures) {
            val md = MessageDigest.getInstance("SHA-256")
            val signatureBytes = signature.toByteArray()
            val digest = md.digest(signatureBytes)
            val actualSignatureHash = bytesToHexString(digest)
            
            if (actualSignatureHash != expectedSignatureHash) {
                return false
            }
        }
        
        return true
    } catch (e: Exception) {
        Log.e("Security", "Error verifying app signature: ${e.message}")
        return false
    }
}

// Convert bytes to hex string
private fun bytesToHexString(bytes: ByteArray): String {
    val hexChars = "0123456789ABCDEF".toCharArray()
    val hexString = StringBuilder(bytes.size * 2)
    
    for (byte in bytes) {
        val i = byte.toInt() and 0xff
        hexString.append(hexChars[i shr 4])
        hexString.append(hexChars[i and 0x0f])
    }
    
    return hexString.toString()
}
```

## OWASP Mobile Top 10 Mitigations for Android

1. **Improper Platform Usage**
   - Follow Android Security Best Practices
   - Use Android Jetpack Security libraries
   - Implement proper permission handling
   - Use WorkManager for background tasks

2. **Insecure Data Storage**
   - Use EncryptedSharedPreferences
   - Use Room with SQLCipher
   - Implement the Android Keystore System
   - Don't store sensitive data in external storage

3. **Insecure Communication**
   - Use Network Security Config
   - Implement certificate pinning
   - Enforce TLS 1.2+ for all connections
   - Validate all certificates

4. **Insecure Authentication**
   - Implement BiometricPrompt API
   - Use OAuth 2.0 or OpenID Connect
   - Store tokens in EncryptedSharedPreferences
   - Implement proper session management

5. **Insufficient Cryptography**
   - Use AndroidX Security Crypto library
   - Follow NIST guidelines for algorithms
   - Use hardware-backed key storage when available
   - Never implement custom cryptography

6. **Insecure Authorization**
   - Implement proper permission checks
   - Use fine-grained access controls
   - Validate user authorization server-side
   - Implement principle of least privilege

7. **Client Code Quality**
   - Use static analysis tools (Android Lint, Detekt)
   - Follow Android coding best practices
   - Implement proper exception handling
   - Use Android Architecture Components

8. **Code Tampering**
   - Verify app signature
   - Implement integrity checks
   - Use SafetyNet Attestation API
   - Implement obfuscation with ProGuard/R8

9. **Reverse Engineering**
   - Use code obfuscation
   - Implement anti-debugging techniques
   - Use string encryption
   - Apply resource encryption

10. **Extraneous Functionality**
    - Remove debug code in release builds
    - Disable developer settings in production
    - Use BuildConfig.DEBUG to gate debug features
    - Audit all app features before release

## Additional Resources

1. [Android Security Overview](https://source.android.com/security)
2. [Android App Security Best Practices](https://developer.android.com/topic/security/best-practices)
3. [Android Security Guide](https://developer.android.com/guide/topics/security)
4. [OWASP Mobile Security Testing Guide for Android](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05a-Platform-Overview.md)
5. [SafetyNet Attestation API](https://developer.android.com/training/safetynet/attestation)
6. [Android Keystore System](https://developer.android.com/training/articles/keystore)
7. [AndroidX Security Library](https://developer.android.com/reference/androidx/security/crypto/package-summary)
````
