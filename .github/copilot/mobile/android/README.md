# Android Security Instructions for GitHub Copilot

This directory contains GitHub Copilot custom instructions specific to secure Android development. These instructions guide Copilot to provide security-focused code suggestions for Android application development using Java and Kotlin.

## Available Instructions

1. [Android Security Instructions](./android-security.md) - Comprehensive Android security instructions for GitHub Copilot

## Key Android Security Areas

The Android security instructions cover these key areas:

1. **Android Secure Storage**
   - EncryptedSharedPreferences implementation
   - Room database with SQLCipher encryption
   - Android Keystore System for key management
   - Secure file storage with proper permissions
   - Secure database operations

2. **Android Network Security**
   - Network Security Config best practices
   - Certificate pinning with OkHttp and standard APIs
   - TLS configuration for secure connections
   - Retrofit/OkHttp security configuration
   - Secure WebView implementation

3. **Android Authentication & Authorization**
   - BiometricPrompt API for biometric authentication
   - Secure token storage techniques
   - OAuth 2.0 implementation for Android
   - Runtime permission handling best practices
   - Multi-factor authentication patterns

4. **Android Component Security**
   - Secure Activity implementation
   - Service security best practices
   - BroadcastReceiver security patterns
   - ContentProvider security configuration
   - Intent security and filtering

5. **Android Platform Security**
   - SafetyNet Attestation API usage
   - Root detection implementation
   - App signature verification
   - Secure Android Manifest configuration
   - StrictMode security policy configuration

6. **Secure Kotlin/Java Patterns**
   - Kotlin security best practices
   - Secure concurrency patterns
   - Memory management security
   - Input validation techniques
   - Android-specific security patterns

## Usage Instructions

### How to Use These Copilot Instructions

1. **Basic Setup**:
   - Copy the entire contents of [android-security.md](./android-security.md)
   - Add them to your GitHub Copilot custom instructions

2. **Combined with Common Mobile Instructions**:
   - For comprehensive coverage, first add the [common mobile security instructions](../common/mobile-security-common.md)
   - Then append these Android-specific instructions
   - This ensures both general and platform-specific security guidance

3. **Customization**:
   - Tailor the instructions based on your specific Android project requirements
   - Add project-specific security requirements or standards
   - Emphasize specific security areas most relevant to your application

4. **Effective Prompting**:
   - When working with Copilot, reference specific security requirements
   - Example: "Implement secure data storage for user credentials using Android Keystore"
   - Ask Copilot to follow the security instructions when generating code

### Benefits

- Consistently secure Android code generation
- Implementation of Android platform security best practices
- Awareness of Android-specific vulnerabilities and mitigations
- Integration with Android security frameworks and APIs
- Guidance on secure configuration of Android components

Use these instructions when developing Android applications to guide Copilot in providing secure code suggestions specific to Android. Combine these with the common mobile security instructions for comprehensive security coverage.
