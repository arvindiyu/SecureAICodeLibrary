# GitHub Copilot Custom Instructions for iOS Development (Swift/SwiftUI)

## General Instructions

As GitHub Copilot, I'll help you write secure iOS code using Swift and SwiftUI. I'll proactively identify potential security issues and suggest best practices specific to the iOS platform, focusing on data protection, secure communications, and proper authentication mechanisms.

## Security Considerations for iOS Development

When suggesting code for iOS applications, I will prioritize these security aspects:

### 1. Secure Data Storage
- I'll suggest using the Keychain Services API for sensitive data
- I'll recommend proper NSFileProtection classes for file security
- I'll warn against storing sensitive data in NSUserDefaults or property lists
- I'll suggest encrypted database solutions like SQLCipher when needed
- I'll recommend secure methods for data caching

**Implementation Focus:**
```swift
// Secure Keychain Implementation
import Security

enum KeychainError: Error {
    case itemNotFound
    case duplicateItem
    case invalidItemFormat
    case unexpectedStatus(OSStatus)
}

class KeychainManager {
    static func save(data: Data, service: String, account: String) throws {
        // Create query for keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // Only accessible when device is unlocked
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete any existing item
        SecItemDelete(query as CFDictionary)
        
        // Add the item to keychain
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    static func load(service: String, account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status != errSecItemNotFound else {
            throw KeychainError.itemNotFound
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        
        guard let data = item as? Data else {
            throw KeychainError.invalidItemFormat
        }
        
        return data
    }
}
```

### 2. Network Security
- I'll suggest proper TLS configuration with App Transport Security (ATS)
- I'll recommend certificate pinning for critical endpoints
- I'll suggest secure request/response handling
- I'll warn against insecure network configurations
- I'll recommend proper error handling for network failures

**Implementation Focus:**
```swift
// Certificate Pinning Implementation
import Foundation

class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    private let pinnedCertificates: [SecCertificate]
    
    init(pinnedCertificateNames: [String]) {
        var certificates: [SecCertificate] = []
        
        for certName in pinnedCertificateNames {
            if let certPath = Bundle.main.path(forResource: certName, ofType: "der"),
               let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)),
               let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                certificates.append(cert)
            }
        }
        
        self.pinnedCertificates = certificates
        super.init()
    }
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Validate the server's certificate chain
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            
            // Set anchor certificates
            SecTrustSetAnchorCertificates(serverTrust, pinnedCertificates as CFArray)
            SecTrustSetAnchorCertificatesOnly(serverTrust, true)
            
            // Evaluate the trust
            var result: SecTrustResultType = .invalid
            SecTrustEvaluate(serverTrust, &result)
            
            let proceed = (result == .proceed || result == .unspecified)
            
            if proceed {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                // Certificate pinning failed
                completionHandler(.cancelAuthenticationChallenge, nil)
                
                // Log the security failure (but don't show details to user)
                os_log("Certificate validation failed", type: .error)
            }
        } else {
            // Not a server trust challenge, cancel
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

// Usage example
let session = URLSession(
    configuration: .default,
    delegate: CertificatePinningDelegate(pinnedCertificateNames: ["api-cert"]),
    delegateQueue: nil
)
```

### 3. Authentication & Authorization
- I'll suggest secure biometric authentication (Face ID / Touch ID)
- I'll recommend proper OAuth 2.0 / OpenID Connect implementation
- I'll suggest secure token storage and refresh mechanisms
- I'll recommend proper session management
- I'll warn against insecure authentication practices

**Implementation Focus:**
```swift
// Secure Biometric Authentication
import LocalAuthentication

enum BiometricError: Error {
    case authenticationFailed
    case userCancel
    case userFallback
    case biometryNotAvailable
    case biometryNotEnrolled
    case biometryLockout
    case unknown
}

class BiometricAuthenticator {
    static func authenticate(reason: String) async throws -> Bool {
        let context = LAContext()
        var authError: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
            if let error = authError {
                switch error.code {
                case LAError.biometryNotAvailable.rawValue:
                    throw BiometricError.biometryNotAvailable
                case LAError.biometryNotEnrolled.rawValue:
                    throw BiometricError.biometryNotEnrolled
                case LAError.biometryLockout.rawValue:
                    throw BiometricError.biometryLockout
                default:
                    throw BiometricError.unknown
                }
            }
            throw BiometricError.unknown
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else {
                    if let error = error as? LAError {
                        switch error.code {
                        case .authenticationFailed:
                            continuation.resume(throwing: BiometricError.authenticationFailed)
                        case .userCancel:
                            continuation.resume(throwing: BiometricError.userCancel)
                        case .userFallback:
                            continuation.resume(throwing: BiometricError.userFallback)
                        case .biometryNotAvailable:
                            continuation.resume(throwing: BiometricError.biometryNotAvailable)
                        case .biometryNotEnrolled:
                            continuation.resume(throwing: BiometricError.biometryNotEnrolled)
                        case .biometryLockout:
                            continuation.resume(throwing: BiometricError.biometryLockout)
                        default:
                            continuation.resume(throwing: BiometricError.unknown)
                        }
                    } else {
                        continuation.resume(throwing: BiometricError.unknown)
                    }
                }
            }
        }
    }
}
```

### 4. App Security Controls
- I'll suggest jailbreak/root detection mechanisms
- I'll recommend secure coding patterns to prevent common iOS vulnerabilities
- I'll suggest proper app-level encryption
- I'll recommend secure data backup handling
- I'll suggest proper app termination practices to clear sensitive data

**Implementation Focus:**
```swift
// Jailbreak Detection
import UIKit
import Darwin

class SecurityUtils {
    static func isDeviceJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        
        // Check for common jailbreak files
        let jailbreakFiles = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        for path in jailbreakFiles {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check if app can open non-standard URL schemes
        if UIApplication.shared.canOpenURL(URL(string: "cydia://")!) {
            return true
        }
        
        // Check if the app can write to a location outside its sandbox
        let stringToWrite = "Jailbreak Test"
        do {
            try stringToWrite.write(
                toFile: "/private/jailbreak.txt",
                atomically: true,
                encoding: .utf8
            )
            // If the write succeeds, the device is jailbroken
            try FileManager.default.removeItem(atPath: "/private/jailbreak.txt")
            return true
        } catch {
            // Write failed, the device is not jailbroken
        }
        
        // Check for suspicious dylib injections
        var count: UInt32 = 0
        if let imageNames = objc_copyImageNames(&count) {
            for i in 0..<count {
                if let imageName = String(
                    cString: imageNames[Int(i)],
                    encoding: .utf8
                ) {
                    if imageName.contains("MobileSubstrate") ||
                       imageName.contains("cycript") ||
                       imageName.contains("Substrate") {
                        return true
                    }
                }
            }
        }
        
        return false
        #endif
    }
    
    static func secureApplicationIfNeeded() {
        if isDeviceJailbroken() {
            // Log security violation
            
            // Option 1: Limit functionality
            // disableSensitiveFeatures()
            
            // Option 2: Alert user and exit
            // showSecurityAlert()
            
            // Option 3: Terminate app immediately
            // exit(0)
        }
    }
}
```

### 5. Cryptography & Privacy
- I'll suggest proper cryptographic APIs (CommonCrypto, CryptoKit)
- I'll warn against deprecated or weak cryptographic algorithms
- I'll suggest proper key management techniques
- I'll recommend privacy best practices (data minimization, purpose limitation)
- I'll suggest proper privacy permission handling

**Implementation Focus:**
```swift
// Secure Encryption with CryptoKit (iOS 13+)
import Foundation
import CryptoKit

enum CryptoError: Error {
    case encryptionFailed
    case decryptionFailed
    case keyGenerationFailed
}

class CryptoService {
    // Generate a random symmetric key and store securely
    static func generateAndStoreKey(identifier: String) throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        
        // Convert to data representation for storage
        let keyData = key.withUnsafeBytes { Data($0) }
        
        try KeychainManager.save(
            data: keyData,
            service: "com.yourapp.encryption",
            account: identifier
        )
        
        return key
    }
    
    // Retrieve key from secure storage
    static func retrieveKey(identifier: String) throws -> SymmetricKey {
        let keyData = try KeychainManager.load(
            service: "com.yourapp.encryption",
            account: identifier
        )
        
        return SymmetricKey(data: keyData)
    }
    
    // Encrypt data using AES-GCM
    static func encrypt(data: Data, using key: SymmetricKey) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
        
        // Combine nonce and ciphertext for storage
        var encryptedData = Data()
        encryptedData.append(nonce.withUnsafeBytes { Data($0) })
        encryptedData.append(sealedBox.ciphertext)
        encryptedData.append(sealedBox.tag)
        
        return encryptedData
    }
    
    // Decrypt data using AES-GCM
    static func decrypt(encryptedData: Data, using key: SymmetricKey) throws -> Data {
        // Extract nonce, ciphertext and tag
        let nonceSize = AES.GCM.Nonce.size
        let tagSize = AES.GCM.TAG_SIZE
        
        guard encryptedData.count > nonceSize + tagSize else {
            throw CryptoError.decryptionFailed
        }
        
        let nonceData = encryptedData.prefix(nonceSize)
        let ciphertext = encryptedData.dropFirst(nonceSize).dropLast(tagSize)
        let tag = encryptedData.suffix(tagSize)
        
        let nonce = try AES.GCM.Nonce(data: nonceData)
        
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
        
        return try AES.GCM.open(sealedBox, using: key)
    }
}
```

## Best Practices I'll Encourage

1. **Secure Data Storage**: Use the Keychain for sensitive data, not UserDefaults or property lists
2. **Network Security**: Implement certificate pinning and proper TLS validation
3. **Input Validation**: Validate and sanitize all user inputs and API responses
4. **Biometric Authentication**: Use LocalAuthentication framework securely
5. **Secure Coding Patterns**: Follow Swift's security features and Apple's secure coding guidelines
6. **App Permissions**: Request only necessary permissions and respect privacy
7. **Cryptography**: Use modern cryptographic APIs (CryptoKit where available)
8. **Secure Defaults**: Configure security settings properly by default
9. **Data Minimization**: Collect and store only required data
10. **Threat Detection**: Implement jailbreak detection and runtime integrity checks

## Anti-patterns I'll Help You Avoid

1. ❌ Storing sensitive data in UserDefaults or plist files
2. ❌ Disabling App Transport Security without specific reasons
3. ❌ Using weak or outdated cryptographic algorithms
4. ❌ Hardcoding credentials or API keys in source code
5. ❌ Using NSLog for sensitive information
6. ❌ Ignoring certificate validation errors
7. ❌ Using UIWebView (deprecated) instead of WKWebView
8. ❌ Implementing custom cryptography instead of platform APIs
9. ❌ Exposing sensitive information in app screenshots
10. ❌ Storing keys or secrets as strings in code

## Security Testing Recommendations

I'll suggest incorporating these testing practices:

1. **Static Analysis**: Use SwiftLint or other static analyzers
2. **Dynamic Analysis**: Test with tools like OWASP ZAP or Burp Suite
3. **Penetration Testing**: Regularly test against OWASP MASVS requirements
4. **Security Review**: Follow Apple's App Store security guidelines
5. **Jailbreak Testing**: Verify jailbreak detection works correctly
6. **Network Testing**: Verify proper TLS configuration and certificate pinning
7. **Cryptography Validation**: Ensure proper implementation of cryptographic APIs
8. **Authentication Testing**: Test biometric and token-based authentication flows
9. **Authorization Testing**: Verify proper access controls
10. **Privacy Testing**: Ensure compliance with App Store privacy requirements
