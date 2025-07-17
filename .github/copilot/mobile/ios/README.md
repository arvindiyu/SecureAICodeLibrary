# iOS Security Instructions for GitHub Copilot

This directory contains GitHub Copilot custom instructions specific to secure iOS development. These instructions guide Copilot to provide security-focused code suggestions for iOS application development using Swift, SwiftUI, and Objective-C.

## Available Instructions

1. [iOS Security Instructions](./ios-security.md) - Comprehensive iOS security instructions for GitHub Copilot

## Key iOS Security Areas

The iOS security instructions cover these key areas:

1. **iOS Secure Storage**
   - Keychain Services API implementation patterns
   - Data Protection API usage with appropriate protection classes
   - Secure CoreData configuration
   - Encrypted SQLite database implementation
   - Secure file handling with proper attributes
   - NSSecureCoding for object serialization

2. **iOS Network Security**
   - App Transport Security (ATS) configuration
   - Certificate pinning with URLSession
   - Secure URLSession configuration
   - Alamofire/AFNetworking security setup
   - Secure API client implementation
   - Preventing common network vulnerabilities

3. **iOS Authentication & Authorization**
   - LocalAuthentication framework for Face ID and Touch ID
   - Secure token management and storage
   - OAuth 2.0 and OpenID Connect implementation
   - Secure authentication flows
   - Multi-factor authentication patterns
   - Session management best practices

4. **iOS App Security**
   - Code signing and validation techniques
   - Provisioning profile security
   - Jailbreak detection implementation
   - App Attest API usage
   - DeviceCheck API implementation
   - Runtime integrity verification
   - Anti-debugging measures

5. **iOS Privacy & Permissions**
   - Permission request best practices
   - Privacy-preserving implementation patterns
   - App Privacy Report preparation
   - Privacy manifests implementation
   - Secure app extension communication
   - App group data sharing security

6. **Secure Swift/SwiftUI Patterns**
   - Swift security best practices
   - SwiftUI security considerations
   - Type-safe programming for security
   - Memory management security
   - Concurrency security with async/await
   - Secure coding patterns for Swift

## Usage Instructions

### How to Use These Copilot Instructions

1. **Basic Setup**:
   - Copy the entire contents of [ios-security.md](./ios-security.md)
   - Add them to your GitHub Copilot custom instructions

2. **Combined with Common Mobile Instructions**:
   - For comprehensive coverage, first add the [common mobile security instructions](../common/mobile-security-common.md)
   - Then append these iOS-specific instructions
   - This ensures both general and platform-specific security guidance

3. **Customization**:
   - Tailor the instructions based on your specific iOS project requirements
   - Add project-specific security requirements or standards
   - Emphasize specific security areas most relevant to your application

4. **Effective Prompting**:
   - When working with Copilot, reference specific security requirements
   - Example: "Implement secure keychain storage for user credentials with biometric protection"
   - Ask Copilot to follow the security instructions when generating code

### Benefits

- Consistently secure iOS code generation
- Implementation of iOS platform security best practices
- Awareness of iOS-specific vulnerabilities and mitigations
- Integration with Apple security frameworks and APIs
- Guidance on secure configuration of iOS app components

Use these instructions when developing iOS applications to guide Copilot in providing secure code suggestions specific to iOS. Combine these with the common mobile security instructions for comprehensive security coverage.
