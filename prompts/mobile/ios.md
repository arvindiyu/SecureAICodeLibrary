# Secure Coding Prompt: iOS Development (Swift/SwiftUI)

## Purpose

This prompt guides you in implementing secure coding practices for iOS applications using Swift and SwiftUI. Use this prompt to generate code that follows iOS security best practices and avoids common mobile application vulnerabilities.

## Secure iOS Development Prompt

```
As a secure iOS developer, help me implement [FEATURE/FUNCTIONALITY] with security as a priority. 

Consider these security aspects in your implementation:
1. Data storage security (Keychain, Data Protection API)
2. Network security (TLS, certificate pinning)
3. Authentication and authorization
4. Input validation and sanitization
5. Protection against common mobile vulnerabilities (insecure data storage, insecure communication)
6. Privacy features (permissions, data minimization)
7. Code signing and provisioning profile security
8. Jailbreak/root detection
9. Biometric authentication implementation
10. Security event logging

Technical requirements:
- iOS version: [minimum iOS version]
- Swift version: [Swift version]
- UI framework: [UIKit, SwiftUI]
- Authentication method: [biometric, OAuth, etc.]
- Data persistence requirements: [local, remote]

Follow these iOS security best practices:
- Use the Keychain Services API for storing sensitive data
- Implement App Transport Security (ATS) properly
- Use URLSession with proper TLS configuration
- Apply Data Protection API with appropriate protection classes
- Validate all user inputs and external data
- Implement proper error handling that doesn't leak sensitive information
- Use SecureEnclave for cryptographic operations when available
- Implement certificate pinning for critical API endpoints
```

## Security Considerations for iOS Development

### Secure Data Storage

- **Keychain Services**: Store sensitive information like tokens, passwords, and encryption keys
- **Data Protection API**: Set proper NSFileProtection classes for files
- **Secure Defaults**: Avoid storing sensitive data in NSUserDefaults, property lists, or Core Data without encryption
- **Encrypted Databases**: Use SQLCipher for encrypted database storage
- **Secure Deletion**: Properly clear sensitive data from memory

### Network Security

- **App Transport Security (ATS)**: Enforce HTTPS connections
- **Certificate Pinning**: Implement certificate or public key pinning for critical endpoints
- **TLS Configuration**: Use proper TLS configurations with strong cipher suites
- **Request/Response Validation**: Validate all server responses
- **Connection Security**: Handle untrusted networks safely

### Authentication & Authorization

- **Biometric Authentication**: Proper implementation of Face ID / Touch ID
- **OAuth 2.0 / OpenID Connect**: Secure implementation of authorization flows
- **Secure Login Persistence**: Store tokens securely in the Keychain
- **Session Management**: Proper session handling and timeout
- **Secure WebView Authentication**: Handle WebView authentication securely

### Secure Coding Practices

- **Input Validation**: Validate and sanitize all user inputs
- **Memory Management**: Avoid buffer overflows and memory leaks
- **Secure Random Number Generation**: Use SecRandomCopyBytes for cryptographically secure random values
- **Swift Memory Safety**: Leverage Swift's memory safety features
- **Code Obfuscation**: Consider obfuscation for highly sensitive applications

## Example Implementation: Secure Keychain Storage

```swift
import Foundation
import Security

enum KeychainError: Error {
    case itemNotFound
    case duplicateItem
    case invalidItemFormat
    case unexpectedStatus(OSStatus)
}

class KeychainService {
    
    // MARK: - Save data to Keychain
    static func saveData(_ data: Data, service: String, account: String) throws {
        
        // Create query dictionary
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete any existing item
        SecItemDelete(query as CFDictionary)
        
        // Add the item to the keychain
        let status = SecItemAdd(query as CFDictionary, nil)
        
        // Throw an error if an unexpected status was returned
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Retrieve data from Keychain
    static func loadData(service: String, account: String) throws -> Data {
        
        // Create query dictionary
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Try to fetch the item from the keychain
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        // Check the return status
        guard status != errSecItemNotFound else {
            throw KeychainError.itemNotFound
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        
        // Cast the item to data and return
        guard let data = item as? Data else {
            throw KeychainError.invalidItemFormat
        }
        
        return data
    }
    
    // MARK: - Update data in Keychain
    static func updateData(_ data: Data, service: String, account: String) throws {
        
        // Create query dictionary
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        // Create attribute dictionary
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        
        // Update the item in the keychain
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        // Throw an error if an unexpected status was returned
        guard status != errSecItemNotFound else {
            throw KeychainError.itemNotFound
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Delete data from Keychain
    static func deleteData(service: String, account: String) throws {
        
        // Create query dictionary
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        // Delete the item from the keychain
        let status = SecItemDelete(query as CFDictionary)
        
        // Return if the item was not found, otherwise throw an error if an unexpected status was returned
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
    
    // MARK: - Convenience methods for storing strings
    static func saveString(_ string: String, service: String, account: String) throws {
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.invalidItemFormat
        }
        try saveData(data, service: service, account: account)
    }
    
    static func loadString(service: String, account: String) throws -> String {
        let data = try loadData(service: service, account: account)
        guard let string = String(data: data, encoding: .utf8) else {
            throw KeychainError.invalidItemFormat
        }
        return string
    }
}
```

## Example Implementation: Certificate Pinning

```swift
import Foundation

class CertificatePinningURLSessionDelegate: NSObject, URLSessionDelegate {
    
    private let pinnedCertificateData: [Data]
    
    init(pinnedCertificateNames: [String]) {
        var certificates: [Data] = []
        
        for certName in pinnedCertificateNames {
            if let certPath = Bundle.main.path(forResource: certName, ofType: "cer"),
               let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) {
                certificates.append(certData)
            }
        }
        
        self.pinnedCertificateData = certificates
        super.init()
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get the server's certificate chain
        let serverCertificatesData = serverCertificates(for: serverTrust)
        
        // Check if any of the pinned certificates match the server certificates
        let serverCertMatch = serverCertificatesData.contains { serverCertData in
            return pinnedCertificateData.contains { pinnedCertData in
                return serverCertData == pinnedCertData
            }
        }
        
        if serverCertMatch {
            // Success! The certificate is trusted
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            // Certificate pinning failed
            completionHandler(.cancelAuthenticationChallenge, nil)
            
            // Report the error (logging, analytics, etc.)
            reportCertificatePinningError()
        }
    }
    
    private func serverCertificates(for serverTrust: SecTrust) -> [Data] {
        var certificates: [Data] = []
        
        // Get the number of certificates in the chain
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        
        for i in 0..<certificateCount {
            if let certificate = SecTrustGetCertificateAtIndex(serverTrust, i),
               let certificateData = SecCertificateCopyData(certificate) as Data? {
                certificates.append(certificateData)
            }
        }
        
        return certificates
    }
    
    private func reportCertificatePinningError() {
        // Implement logging, analytics, or other error reporting here
        print("⚠️ Certificate pinning failed - potential security breach!")
    }
}

// Example usage
func createSecureURLSession() -> URLSession {
    let delegate = CertificatePinningURLSessionDelegate(pinnedCertificateNames: ["api-example-com"])
    
    let configuration = URLSessionConfiguration.default
    // Add additional security headers
    configuration.httpAdditionalHeaders = [
        "X-Requested-With": "XMLHttpRequest"
    ]
    
    return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
}
```

## Example Implementation: Biometric Authentication

```swift
import Foundation
import LocalAuthentication

enum BiometricAuthError: Error {
    case notAvailable
    case notEnrolled
    case lockout
    case denied
    case canceled
    case unknown(Error?)
}

class BiometricAuthService {
    
    static let shared = BiometricAuthService()
    
    private let context = LAContext()
    
    // Check if biometric authentication is available
    func canUseBiometrics() -> (Bool, BiometricAuthError?) {
        var error: NSError?
        
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        if let error = error {
            switch error.code {
            case LAError.biometryNotAvailable.rawValue:
                return (false, .notAvailable)
            case LAError.biometryNotEnrolled.rawValue:
                return (false, .notEnrolled)
            case LAError.biometryLockout.rawValue:
                return (false, .lockout)
            default:
                return (false, .unknown(error))
            }
        }
        
        return (canEvaluate, nil)
    }
    
    // Get biometric type (Face ID or Touch ID)
    func getBiometricType() -> String {
        switch context.biometryType {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .none:
            return "None"
        @unknown default:
            return "Unknown"
        }
    }
    
    // Authenticate with biometrics
    func authenticateWithBiometrics(reason: String, completion: @escaping (Result<Bool, BiometricAuthError>) -> Void) {
        let (canUseBio, error) = canUseBiometrics()
        
        guard canUseBio else {
            completion(.failure(error ?? .notAvailable))
            return
        }
        
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                if success {
                    completion(.success(true))
                } else if let error = error as? LAError {
                    switch error.code {
                    case .userCancel, .appCancel, .systemCancel:
                        completion(.failure(.canceled))
                    case .authenticationFailed:
                        completion(.failure(.denied))
                    case .biometryLockout:
                        completion(.failure(.lockout))
                    default:
                        completion(.failure(.unknown(error)))
                    }
                } else {
                    completion(.failure(.unknown(error)))
                }
            }
        }
    }
}
```

## Security Testing for iOS

### Automated Testing

- Use SwiftLint to check for security and coding issues
- Implement XCTest test cases for security features
- Use OWASP MASVS as a guide for testing security requirements

### Common Vulnerabilities to Test

- **Insecure Data Storage**: Verify sensitive data is stored securely
- **Insecure Communication**: Test SSL/TLS configuration and certificate pinning
- **Authentication Issues**: Verify biometric and token-based authentication
- **Code Tampering**: Test integrity checks and jailbreak detection
- **Information Leakage**: Check for sensitive data in logs or error messages

## References

- Apple Secure Coding Guide: https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html
- OWASP Mobile Security Testing Guide: https://owasp.org/www-project-mobile-security-testing-guide/
- OWASP Mobile Application Security Verification Standard (MASVS): https://mas.owasp.org/
