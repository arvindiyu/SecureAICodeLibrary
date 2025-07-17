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
8. Jailbreak detection
9. Biometric authentication implementation (Face ID, Touch ID)
10. Security event logging
11. App extension security (widgets, share extensions)
12. Secure Swift coding patterns
13. App Attest API implementation
14. DeviceCheck API usage
15. Anti-screenshot/screen recording protections

Technical requirements:
- iOS version: [minimum iOS version]
- Swift version: [Swift version]
- UI framework: [UIKit, SwiftUI]
- Authentication method: [biometric, OAuth, etc.]
- Data persistence requirements: [local, remote]
- Security compliance requirements: [OWASP MASVS level, PCI-DSS, HIPAA, etc.]

Follow these iOS security best practices:
- Use the Keychain Services API for storing sensitive data
- Implement App Transport Security (ATS) properly
- Use URLSession with proper TLS configuration
- Apply Data Protection API with appropriate protection classes
- Validate all user inputs and external data
- Implement proper error handling that doesn't leak sensitive information
- Use SecureEnclave for cryptographic operations when available
- Implement certificate pinning for critical API endpoints
- Use Swift's type-safety features to prevent injection attacks
- Implement security measures for SwiftUI previews and debugging
- Apply secure coding patterns for concurrency (async/await, actors)
- Use Privacy Manifests for App Privacy Report transparency
```

## Security Considerations for iOS Development

### Secure Data Storage

#### Keychain Services

```swift
import Security
import Foundation

/**
 SecureKeychainManager - A secure wrapper for iOS Keychain Services
 
 Provides methods to securely store, retrieve, update, and delete sensitive data
 from the iOS Keychain with proper error handling and security attributes.
 */
class SecureKeychainManager {
    
    // Service identifier for the keychain items
    private let serviceIdentifier: String
    
    // Access group for keychain sharing (optional)
    private let accessGroup: String?
    
    /**
     Initialize the keychain manager
     
     - Parameters:
        - serviceIdentifier: The service identifier for keychain items
        - accessGroup: Optional access group for keychain sharing between apps with the same team ID
     */
    init(serviceIdentifier: String, accessGroup: String? = nil) {
        self.serviceIdentifier = serviceIdentifier
        self.accessGroup = accessGroup
    }
    
    /**
     Store a string securely in the keychain
     
     - Parameters:
        - key: The key to associate with the stored value
        - value: The string value to store securely
        - accessControl: The access control context (defaults to whenUnlockedThisDeviceOnly)
     
     - Returns: True if the operation was successful, false otherwise
     */
    func storeSecureString(_ value: String, forKey key: String, 
                          withAccessControl accessControl: SecAccessControlCreateFlags = .biometryCurrentSet) -> Bool {
        
        // Convert string to data
        guard let valueData = value.data(using: .utf8) else {
            print("Failed to convert string to data")
            return false
        }
        
        // Create access control object
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControl,
            &error
        ) else {
            print("Failed to create access control: \(error.debugDescription)")
            return false
        }
        
        // Create query dictionary with secure attributes
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: serviceIdentifier,
            kSecValueData as String: valueData,
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        
        // Add access group if specified
        var finalQuery = query
        if let accessGroup = accessGroup {
            finalQuery[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Delete any existing item first
        SecItemDelete(finalQuery as CFDictionary)
        
        // Add the new keychain item
        let status = SecItemAdd(finalQuery as CFDictionary, nil)
        
        return status == errSecSuccess
    }
    
    /**
     Retrieve a securely stored string from the keychain
     
     - Parameters:
        - key: The key associated with the stored value
     
     - Returns: The retrieved string or nil if not found or an error occurred
     */
    func getSecureString(forKey key: String) -> String? {
        // Create query dictionary
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: serviceIdentifier,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: kCFBooleanTrue as Any
        ]
        
        // Add access group if specified
        var finalQuery = query
        if let accessGroup = accessGroup {
            finalQuery[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Query the keychain
        var item: CFTypeRef?
        let status = SecItemCopyMatching(finalQuery as CFDictionary, &item)
        
        // Check if successful
        guard status == errSecSuccess,
              let data = item as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return string
    }
    
    /**
     Update a securely stored string in the keychain
     
     - Parameters:
        - key: The key associated with the value to update
        - newValue: The new string value
     
     - Returns: True if the operation was successful, false otherwise
     */
    func updateSecureString(_ newValue: String, forKey key: String) -> Bool {
        // Convert string to data
        guard let valueData = newValue.data(using: .utf8) else {
            print("Failed to convert string to data")
            return false
        }
        
        // Create query to find the item
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: serviceIdentifier
        ]
        
        // Add access group if specified
        var finalQuery = query
        if let accessGroup = accessGroup {
            finalQuery[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Create attributes for the update
        let attributes: [String: Any] = [
            kSecValueData as String: valueData
        ]
        
        // Update the item
        let status = SecItemUpdate(finalQuery as CFDictionary, attributes as CFDictionary)
        
        // If item doesn't exist, try to create it
        if status == errSecItemNotFound {
            return storeSecureString(newValue, forKey: key)
        }
        
        return status == errSecSuccess
    }
    
    /**
     Delete a securely stored item from the keychain
     
     - Parameters:
        - key: The key associated with the value to delete
     
     - Returns: True if the operation was successful, false otherwise
     */
    func deleteSecureItem(forKey key: String) -> Bool {
        // Create query to find the item
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: serviceIdentifier
        ]
        
        // Add access group if specified
        var finalQuery = query
        if let accessGroup = accessGroup {
            finalQuery[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Delete the item
        let status = SecItemDelete(finalQuery as CFDictionary)
        
        // Consider success if item was deleted or wasn't found
        return status == errSecSuccess || status == errSecItemNotFound
    }
    
    /**
     Check if an item exists in the keychain
     
     - Parameters:
        - key: The key to check
     
     - Returns: True if the item exists, false otherwise
     */
    func secureItemExists(forKey key: String) -> Bool {
        // Create query to find the item
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: serviceIdentifier,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: false
        ]
        
        // Add access group if specified
        var finalQuery = query
        if let accessGroup = accessGroup {
            finalQuery[kSecAttrAccessGroup as String] = accessGroup
        }
        
        // Check if item exists
        let status = SecItemCopyMatching(finalQuery as CFDictionary, nil)
        
        return status == errSecSuccess
    }
}
```

#### Data Protection API Usage

```swift
import Foundation

/**
 SecureFileManager - A wrapper for secure file operations using Data Protection
 
 Ensures files are stored with proper Data Protection attributes
 */
class SecureFileManager {
    
    // The file manager instance
    private let fileManager = FileManager.default
    
    /**
     Save data to a file with Data Protection enabled
     
     - Parameters:
        - data: The data to save
        - filename: The filename to save to
        - directory: The directory to save in
        - protection: The data protection level to apply
     
     - Returns: The URL of the saved file, or nil if saving failed
     */
    func saveDataSecurely(_ data: Data,
                          filename: String,
                          directory: FileManager.SearchPathDirectory = .documentDirectory,
                          protection: FileProtectionType = .completeUntilFirstUserAuthentication) -> URL? {
        
        do {
            // Get the document directory
            let directoryURL = try fileManager.url(for: directory, 
                                                  in: .userDomainMask, 
                                                  appropriateFor: nil, 
                                                  create: true)
            
            // Create the file URL
            let fileURL = directoryURL.appendingPathComponent(filename)
            
            // Write the data
            try data.write(to: fileURL, options: .atomic)
            
            // Set data protection
            try fileManager.setAttributes([.protectionKey: protection], ofItemAtPath: fileURL.path)
            
            return fileURL
        } catch {
            print("Error saving file securely: \(error.localizedDescription)")
            return nil
        }
    }
    
    /**
     Read data from a secure file
     
     - Parameters:
        - filename: The name of the file to read
        - directory: The directory to read from
     
     - Returns: The data from the file, or nil if reading failed
     */
    func readSecureFile(filename: String,
                        directory: FileManager.SearchPathDirectory = .documentDirectory) -> Data? {
        
        do {
            // Get the document directory
            let directoryURL = try fileManager.url(for: directory, 
                                                  in: .userDomainMask, 
                                                  appropriateFor: nil, 
                                                  create: false)
            
            // Get the file URL
            let fileURL = directoryURL.appendingPathComponent(filename)
            
            // Read the data
            return try Data(contentsOf: fileURL)
        } catch {
            print("Error reading secure file: \(error.localizedDescription)")
            return nil
        }
    }
    
    /**
     Delete a secure file
     
     - Parameters:
        - filename: The name of the file to delete
        - directory: The directory containing the file
     
     - Returns: True if deletion was successful, false otherwise
     */
    func deleteSecureFile(filename: String,
                          directory: FileManager.SearchPathDirectory = .documentDirectory) -> Bool {
        
        do {
            // Get the document directory
            let directoryURL = try fileManager.url(for: directory, 
                                                  in: .userDomainMask, 
                                                  appropriateFor: nil, 
                                                  create: false)
            
            // Get the file URL
            let fileURL = directoryURL.appendingPathComponent(filename)
            
            // Check if file exists
            if fileManager.fileExists(atPath: fileURL.path) {
                // Delete the file
                try fileManager.removeItem(at: fileURL)
                return true
            } else {
                return false
            }
        } catch {
            print("Error deleting secure file: \(error.localizedDescription)")
            return false
        }
    }
}
```

### Network Security

#### App Transport Security

```swift
// In Info.plist
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSRequiresCertificateTransparency</key>
            <true/>
        </dict>
    </dict>
</dict>
```

#### Certificate Pinning with URLSession

```swift
import Foundation

/**
 SecureNetworkManager - A secure networking implementation with certificate pinning
 
 Uses URLSession with proper TLS configuration and certificate pinning
 to prevent man-in-the-middle attacks
 */
class SecureNetworkManager: NSObject, URLSessionDelegate {
    
    // Singleton instance
    static let shared = SecureNetworkManager()
    
    // URLSession configured with this class as the delegate
    lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30.0
        configuration.timeoutIntervalForResource = 60.0
        
        // Add security headers to all requests
        configuration.httpAdditionalHeaders = [
            "X-Requested-With": "XMLHttpRequest",
            "X-Platform": "iOS"
        ]
        
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()
    
    // The pinned certificates
    private let pinnedCertificates: [Data] = {
        let certsURL = Bundle.main.url(forResource: "pinned-certs", withExtension: "bundle")
        let certsBundle = Bundle(url: certsURL!)
        
        // Get all certificates in the bundle
        var certificates: [Data] = []
        if let certURLs = certsBundle?.urls(forResourcesWithExtension: "der", subdirectory: nil) {
            for url in certURLs {
                if let certData = try? Data(contentsOf: url) {
                    certificates.append(certData)
                }
            }
        }
        
        return certificates
    }()
    
    // Private initializer for singleton pattern
    private override init() {
        super.init()
    }
    
    /**
     Implements certificate pinning for URLSession
     */
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge, 
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Check if this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            // Reject non-server trust challenges
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get server certificate
        let serverCertificatesCount = SecTrustGetCertificateCount(serverTrust)
        guard serverCertificatesCount > 0,
              let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Convert server certificate to Data for comparison
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        // Check if server certificate matches any of our pinned certificates
        if pinnedCertificates.contains(serverCertificateData) {
            // Certificate matches, proceed
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            // Certificate pinning failed, cancel the request
            completionHandler(.cancelAuthenticationChallenge, nil)
            // Log security incident (potential MITM attack)
            logSecurityIncident(message: "Certificate pinning failed for \(challenge.protectionSpace.host)")
        }
    }
    
    /**
     Make a secure GET request
     
     - Parameters:
        - urlString: The URL to request
        - completion: Completion handler with result
     */
    func secureGet(urlString: String, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(.failure(NetworkError.invalidURL))
            return
        }
        
        let task = session.dataTask(with: url) { (data, response, error) in
            // Check for errors
            if let error = error {
                completion(.failure(error))
                return
            }
            
            // Verify HTTP response
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NetworkError.invalidResponse))
                return
            }
            
            // Check status code
            switch httpResponse.statusCode {
            case 200..<300:
                if let data = data {
                    completion(.success(data))
                } else {
                    completion(.failure(NetworkError.noData))
                }
            case 401:
                completion(.failure(NetworkError.unauthorized))
            case 403:
                completion(.failure(NetworkError.forbidden))
            case 404:
                completion(.failure(NetworkError.notFound))
            default:
                completion(.failure(NetworkError.serverError(statusCode: httpResponse.statusCode)))
            }
        }
        
        task.resume()
    }
    
    /**
     Make a secure POST request
     
     - Parameters:
        - urlString: The URL to request
        - body: The data to send in the request body
        - completion: Completion handler with result
     */
    func securePost(urlString: String, body: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(.failure(NetworkError.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let task = session.dataTask(with: request) { (data, response, error) in
            // Check for errors
            if let error = error {
                completion(.failure(error))
                return
            }
            
            // Verify HTTP response
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NetworkError.invalidResponse))
                return
            }
            
            // Check status code
            switch httpResponse.statusCode {
            case 200..<300:
                if let data = data {
                    completion(.success(data))
                } else {
                    completion(.failure(NetworkError.noData))
                }
            case 401:
                completion(.failure(NetworkError.unauthorized))
            case 403:
                completion(.failure(NetworkError.forbidden))
            case 404:
                completion(.failure(NetworkError.notFound))
            default:
                completion(.failure(NetworkError.serverError(statusCode: httpResponse.statusCode)))
            }
        }
        
        task.resume()
    }
    
    /**
     Log security incidents without exposing sensitive details
     */
    private func logSecurityIncident(message: String) {
        // In production, use a secure logging mechanism
        #if DEBUG
        print("Security Incident: \(message)")
        #else
        // Minimal logging in release builds
        // Send to secure logging service if available
        #endif
    }
}

/**
 Enum representing network errors
 */
enum NetworkError: Error {
    case invalidURL
    case invalidResponse
    case noData
    case unauthorized
    case forbidden
    case notFound
    case serverError(statusCode: Int)
}
```

### Authentication & Authorization

#### Biometric Authentication with LocalAuthentication

```swift
import LocalAuthentication

class BiometricAuthManager {
    enum BiometricType {
        case none
        case touchID
        case faceID
        
        var description: String {
            switch self {
            case .none: return "None"
            case .touchID: return "Touch ID"
            case .faceID: return "Face ID"
            }
        }
    }
    
    enum BiometricError: Error {
        case authenticationFailed
        case userCancel
        case userFallback
        case biometryNotAvailable
        case biometryNotEnrolled
        case biometryLockout
        case unknown
    }
    
    static func getBiometricType() -> BiometricType {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        if #available(iOS 11.0, *) {
            switch context.biometryType {
            case .none:
                return .none
            case .touchID:
                return .touchID
            case .faceID:
                return .faceID
            @unknown default:
                return .none
            }
        } else {
            return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) ? .touchID : .none
        }
    }
    
    static func authenticateUser(reason: String, completion: @escaping (Result<Bool, BiometricError>) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            // Authenticate with biometrics
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                DispatchQueue.main.async {
                    if success {
                        completion(.success(true))
                    } else {
                        if let error = error as? LAError {
                            switch error.code {
                            case .authenticationFailed:
                                completion(.failure(.authenticationFailed))
                            case .userCancel:
                                completion(.failure(.userCancel))
                            case .userFallback:
                                completion(.failure(.userFallback))
                            case .biometryNotAvailable:
                                completion(.failure(.biometryNotAvailable))
                            case .biometryNotEnrolled:
                                completion(.failure(.biometryNotEnrolled))
                            case .biometryLockout:
                                completion(.failure(.biometryLockout))
                            default:
                                completion(.failure(.unknown))
                            }
                        } else {
                            completion(.failure(.unknown))
                        }
                    }
                }
            }
        } else {
            DispatchQueue.main.async {
                if let error = error as? LAError {
                    switch error.code {
                    case .biometryNotEnrolled:
                        completion(.failure(.biometryNotEnrolled))
                    case .biometryNotAvailable:
                        completion(.failure(.biometryNotAvailable))
                    case .biometryLockout:
                        completion(.failure(.biometryLockout))
                    default:
                        completion(.failure(.unknown))
                    }
                } else {
                    completion(.failure(.unknown))
                }
            }
        }
    }
    
    // Secure data with biometric authentication
    static func secureData(_ data: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        authenticateUser(reason: "Encrypt sensitive data") { result in
            switch result {
            case .success:
                do {
                    let encryptedData = try self.encryptData(data)
                    completion(.success(encryptedData))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    // Helper method to encrypt data
    private static func encryptData(_ data: Data) throws -> Data {
        // Get access to the keychain
        let tag = "com.example.app.encryption.key".data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &item)
        
        var key: SecKey
        
        if status == errSecItemNotFound {
            // Key doesn't exist, create it
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                        nil,
                        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                        .userPresence,
                        nil
                    )!
                ]
            ]
            
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            
            key = privateKey
        } else if status == errSecSuccess {
            // Key exists, use it
            key = (item as! SecKey)
        } else {
            throw NSError(domain: "com.example.app", code: Int(status), userInfo: nil)
        }
        
        // Get the public key
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw NSError(domain: "com.example.app", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to get public key"])
        }
        
        // Encrypt the data
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return encryptedData
    }
}
```

### Jailbreak Detection

```swift
func isDeviceJailbroken() -> Bool {
    // Check for common jailbreak files
    let jailbreakFilepaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt"
    ]
    
    for path in jailbreakFilepaths {
        if FileManager.default.fileExists(atPath: path) {
            return true
        }
    }
    
    // Check if app can write to system directories
    let restrictedDirectories = [
        "/",
        "/private",
        "/root"
    ]
    
    for directory in restrictedDirectories {
        let file = "\(directory)/test_jailbreak.txt"
        do {
            try "test".write(toFile: file, atomically: true, encoding: .utf8)
            // If we get here, the write succeeded, which shouldn't be possible
            try FileManager.default.removeItem(atPath: file)
            return true
        } catch {
            // Expected failure on non-jailbroken devices
        }
    }
    
    // Check for Cydia URL scheme
    if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
        return true
    }
    
    // Check for suspicious environment variables
    if ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil {
        return true
    }
    
    return false
}

// Use in your app
if isDeviceJailbroken() {
    // Take appropriate action (e.g., warn user, limit functionality, exit app)
    let alert = UIAlertController(
        title: "Security Warning",
        message: "This app doesn't support jailbroken devices for security reasons.",
        preferredStyle: .alert
    )
    
    alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
        // Consider exiting the app or limiting functionality
        exit(0)
    })
    
    // Present the alert
    DispatchQueue.main.async {
        UIApplication.shared.windows.first?.rootViewController?.present(alert, animated: true)
    }
}
```

### Secure Logging

```swift
import os.log

class SecureLogger {
    enum LogLevel {
        case debug
        case info
        case warning
        case error
        case security
        
        var osLogType: OSLogType {
            switch self {
            case .debug: return .debug
            case .info: return .info
            case .warning: return .default
            case .error: return .error
            case .security: return .fault
            }
        }
    }
    
    private static let subsystem = Bundle.main.bundleIdentifier ?? "com.example.app"
    private static let generalLog = OSLog(subsystem: subsystem, category: "general")
    private static let securityLog = OSLog(subsystem: subsystem, category: "security")
    private static let networkLog = OSLog(subsystem: subsystem, category: "network")
    
    private static let isLoggingEnabled = !isAppStoreRelease()
    private static let isSecurityLoggingEnabled = true // Always log security events
    
    private static func isAppStoreRelease() -> Bool {
        #if DEBUG
            return false
        #else
            // Check if running from App Store or TestFlight
            guard let appStoreReceiptURL = Bundle.main.appStoreReceiptURL else {
                return false
            }
            return appStoreReceiptURL.lastPathComponent != "sandboxReceipt"
        #endif
    }
    
    static func log(_ message: String, level: LogLevel = .info, category: OSLog = generalLog, includePrivateData: Bool = false) {
        // Don't log debug messages in release builds
        if level == .debug && !isLoggingEnabled {
            return
        }
        
        // Always log security events
        if category == securityLog || level == .security {
            if includePrivateData {
                os_log("%{private}@", log: securityLog, type: level.osLogType, message)
            } else {
                os_log("%{public}@", log: securityLog, type: level.osLogType, message)
            }
            
            // For critical security events, consider additional reporting
            if level == .security {
                // Send to security monitoring system or store for later analysis
                storeSecurityEvent(message: message)
            }
        } else if isLoggingEnabled {
            if includePrivateData {
                os_log("%{private}@", log: category, type: level.osLogType, message)
            } else {
                os_log("%{public}@", log: category, type: level.osLogType, message)
            }
        }
    }
    
    // Log network requests without sensitive information
    static func logNetworkRequest(url: URL, method: String) {
        // Redact any sensitive parameters from URL
        var components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        
        // Remove sensitive query items
        if let queryItems = components?.queryItems {
            let sensitiveParameters = ["token", "key", "password", "secret", "auth"]
            components?.queryItems = queryItems.map { item in
                if sensitiveParameters.contains(item.name.lowercased()) {
                    return URLQueryItem(name: item.name, value: "REDACTED")
                } else {
                    return item
                }
            }
        }
        
        let safeUrlString = components?.url?.absoluteString ?? "URL parsing failed"
        log("Network \(method) request: \(safeUrlString)", category: networkLog)
    }
    
    // Store security events for later analysis
    private static func storeSecurityEvent(message: String) {
        let event = SecurityEvent(
            timestamp: Date(),
            message: message,
            deviceID: UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
        )
        
        // Store event securely
        do {
            let encoder = JSONEncoder()
            let data = try encoder.encode(event)
            try storeSecurityEventData(data)
        } catch {
            os_log("Failed to store security event: %{public}@", log: securityLog, type: .error, error.localizedDescription)
        }
    }
    
    // Store security event data for later sending to server
    private static func storeSecurityEventData(_ data: Data) throws {
        let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let eventsDirectory = documentsDirectory.appendingPathComponent("SecurityEvents")
        
        // Create directory if it doesn't exist
        if !FileManager.default.fileExists(atPath: eventsDirectory.path) {
            try FileManager.default.createDirectory(at: eventsDirectory, withIntermediateDirectories: true)
        }
        
        // Create a unique filename
        let filename = "security_event_\(Date().timeIntervalSince1970).json"
        let fileURL = eventsDirectory.appendingPathComponent(filename)
        
        // Write the data
        try data.write(to: fileURL)
        
        // Set data protection
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        resourceValues.protectionKey = .completeFileProtection
        
        try fileURL.setResourceValues(resourceValues)
    }
}

// Security event model
struct SecurityEvent: Codable {
    let timestamp: Date
    let message: String
    let deviceID: String
}

// Usage examples
SecureLogger.log("User authenticated successfully", level: .info)
SecureLogger.log("Failed login attempt: incorrect password", level: .warning)
SecureLogger.log("User personal data: \(userData)", level: .debug, includePrivateData: true)
SecureLogger.log("Possible security breach: multiple failed login attempts", level: .security)
```

## iOS Security Testing Guide

1. **Data Storage**
   - Check Keychain usage for sensitive data
   - Review Data Protection API implementation
   - Verify proper encryption of local files
   - Audit backup settings for sensitive files

2. **Network Security**
   - Verify proper ATS implementation
   - Test certificate pinning implementation
   - Check for HTTPS usage across all communications
   - Validate certificate validation logic

3. **Authentication & Authorization**
   - Test biometric authentication implementation
   - Verify secure storage of authentication tokens
   - Check session management and expiration
   - Test authorization controls

4. **Code Protection**
   - Verify jailbreak detection mechanisms
   - Check for anti-debugging measures
   - Audit app against reverse engineering
   - Test runtime manipulation defenses

5. **Privacy**
   - Review permission usage and requests
   - Verify data minimization practices
   - Check privacy settings implementation
   - Audit data collection and sharing

## Additional Resources

1. [Apple Security Documentation](https://developer.apple.com/documentation/security)
2. [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
3. [OWASP Mobile Security Testing Guide for iOS](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06-iOS-Platform-Overview.md)
4. [Apple App Transport Security](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
5. [Keychain Services Programming Guide](https://developer.apple.com/documentation/security/keychain_services)
6. [Local Authentication Framework](https://developer.apple.com/documentation/localauthentication)
7. [Data Protection API](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_data)
