# Secure Cryptography Implementation Guide

This guide provides best practices for implementing cryptographic solutions across different programming languages and use cases.

## Core Principles

1. **Never implement your own cryptographic algorithms**
   - Always use established, peer-reviewed libraries and algorithms
   - Focus on correct implementation rather than creating custom solutions

2. **Use current industry standard algorithms**
   - Prefer AES-256 for symmetric encryption
   - Use RSA-2048/4096, ECC (P-256 or higher) for asymmetric encryption
   - Use SHA-256 or SHA-3 for hashing
   - Use Argon2, bcrypt, or PBKDF2 with sufficient iterations for password hashing
   - Prefer ChaCha20-Poly1305 or AES-GCM for authenticated encryption

3. **Secure key management**
   - Never hardcode keys or store them in code repositories
   - Use hardware security modules (HSM) or key management services when possible
   - Implement key rotation policies
   - Protect keys at rest with strong access controls

4. **Encryption contexts**
   - Properly manage initialization vectors (IVs) - use securely generated random IVs
   - For CBC mode: use unique, random IVs for each encryption operation
   - For GCM mode: never reuse the same (key, IV) pair

5. **Authenticated Encryption**
   - Always use authenticated encryption (AEAD) algorithms like AES-GCM or ChaCha20-Poly1305
   - If using AES-CBC, implement proper MAC (Message Authentication Code) with HMAC

## Language-Specific Implementation Examples

### Python

```python
# Symmetric Encryption using AES-GCM (using cryptography library)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_data(data: bytes, key: bytes) -> tuple:
    """Encrypt data using AES-GCM with a secure random nonce"""
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    
    # Generate a random 96-bit (12 byte) nonce for AES-GCM
    nonce = os.urandom(12)
    
    # Create the AESGCM instance with the provided key
    aesgcm = AESGCM(key)
    
    # Encrypt the data with an empty associated data
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    return (nonce, ciphertext)

def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-GCM with the provided nonce"""
    aesgcm = AESGCM(key)
    
    # Decrypt the data
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext

# Usage example
if __name__ == "__main__":
    # Generate a secure random key (32 bytes for AES-256)
    key = os.urandom(32)
    
    # Data to encrypt
    data = "Sensitive data to encrypt"
    
    # Encrypt the data
    nonce, ciphertext = encrypt_data(data, key)
    
    # Decrypt the data
    decrypted_data = decrypt_data(nonce, ciphertext, key)
    print(decrypted_data.decode('utf-8'))  # Should print the original message

# Secure Password Hashing with Argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

def hash_password(password: str) -> str:
    """Hash a password using Argon2id"""
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
    return ph.hash(password)

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify a password against a stored hash"""
    ph = PasswordHasher()
    try:
        ph.verify(stored_hash, provided_password)
        return True
    except VerifyMismatchError:
        return False
```

### JavaScript/TypeScript (Node.js)

```typescript
// Symmetric Encryption using AES-GCM with Node.js crypto
import * as crypto from 'crypto';

interface EncryptedData {
  iv: string;
  ciphertext: string;
  tag: string;
}

function generateKey(): Buffer {
  // Generate a secure random 256-bit key
  return crypto.randomBytes(32);
}

function encryptData(data: string, key: Buffer): EncryptedData {
  // Generate a random 96-bit IV
  const iv = crypto.randomBytes(12);
  
  // Create cipher with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  // Encrypt the data
  let ciphertext = cipher.update(data, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  
  // Get the authentication tag
  const tag = cipher.getAuthTag().toString('base64');
  
  return {
    iv: iv.toString('base64'),
    ciphertext,
    tag
  };
}

function decryptData(encryptedData: EncryptedData, key: Buffer): string {
  // Create decipher with AES-256-GCM
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(encryptedData.iv, 'base64')
  );
  
  // Set auth tag
  decipher.setAuthTag(Buffer.from(encryptedData.tag, 'base64'));
  
  // Decrypt the data
  let decrypted = decipher.update(encryptedData.ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Password hashing with bcrypt
import * as bcrypt from 'bcrypt';

async function hashPassword(password: string): Promise<string> {
  // Generate a salt with cost factor 12 (adjust based on your performance requirements)
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(storedHash: string, providedPassword: string): Promise<boolean> {
  return await bcrypt.compare(providedPassword, storedHash);
}
```

### Java

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.KeyGenerator;

public class SecureCrypto {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;  // 128 bits

    // Generate a secure AES-256 key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    // Encrypt data using AES-GCM
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // Create the cipher instance
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        
        // Initialize the cipher for encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        // Encrypt
        byte[] cipherText = cipher.doFinal(plaintext.getBytes("UTF-8"));
        
        // Combine IV and ciphertext
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }

    // Decrypt data using AES-GCM
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        // Decode the combined data
        byte[] combined = Base64.getDecoder().decode(encryptedText);
        
        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] cipherText = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, cipherText, 0, cipherText.length);
        
        // Create the cipher instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        
        // Initialize the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        
        // Decrypt
        byte[] plainText = cipher.doFinal(cipherText);
        
        return new String(plainText, "UTF-8");
    }
}

// For password hashing, use a library like BCrypt or jBCrypt
import org.mindrot.jbcrypt.BCrypt;

public class PasswordUtils {
    // Hash a password using BCrypt
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12)); // Work factor 12
    }
    
    // Verify a password against a stored hash
    public static boolean verifyPassword(String password, String storedHash) {
        return BCrypt.checkpw(password, storedHash);
    }
}
```

### Go

```go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// GenerateKey generates a secure random key for AES-256
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes = 256 bits
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAESGCM encrypts data using AES-GCM
func EncryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	// Create the AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and seal the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data encrypted with AES-GCM
func DecryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	// Create the AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check for valid ciphertext length
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptToBase64 encrypts data and returns as base64 string
func EncryptToBase64(plaintext string, key []byte) (string, error) {
	ciphertext, err := EncryptAESGCM([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptFromBase64 decrypts base64 encoded data
func DecryptFromBase64(encoded string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	
	plaintext, err := DecryptAESGCM(ciphertext, key)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}

// HashPasswordBcrypt hashes a password using bcrypt
func HashPasswordBcrypt(password string) (string, error) {
	// Cost of 12 is a good balance between security and performance
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// CheckPasswordBcrypt checks if a password matches a bcrypt hash
func CheckPasswordBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPasswordArgon2id hashes a password using Argon2id
func HashPasswordArgon2id(password string) string {
	// Parameters for Argon2id
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err) // In production code, handle errors properly
	}
	
	// time=3, memory=64*1024 (64MB), threads=4, keyLength=32
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	
	// Encode salt and hash to base64
	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	hashBase64 := base64.StdEncoding.EncodeToString(hash)
	
	// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	return "$argon2id$v=19$m=65536,t=3,p=4$" + saltBase64 + "$" + hashBase64
}
```

### C# (.NET)

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class SecureCrypto
{
    // Generate a secure random AES-256 key
    public static byte[] GenerateKey()
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.GenerateKey();
            return aes.Key;
        }
    }

    // Encrypt data using AES-GCM
    public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptAesGcm(byte[] plaintext, byte[] key)
    {
        // Generate a random nonce (12 bytes is recommended for GCM)
        byte[] nonce = new byte[12];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonce);
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16]; // 128-bit authentication tag

        // Encrypt the data
        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        return (ciphertext, nonce, tag);
    }

    // Decrypt data using AES-GCM
    public static byte[] DecryptAesGcm(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        byte[] plaintext = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return plaintext;
    }

    // Encrypt a string and return as Base64
    public static string EncryptToBase64(string plaintext, byte[] key)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        
        var (ciphertext, nonce, tag) = EncryptAesGcm(plaintextBytes, key);
        
        // Combine nonce, tag, and ciphertext
        byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);
        
        return Convert.ToBase64String(result);
    }

    // Decrypt from Base64 string
    public static string DecryptFromBase64(string base64Ciphertext, byte[] key)
    {
        byte[] combined = Convert.FromBase64String(base64Ciphertext);
        
        // Extract nonce, tag, and ciphertext
        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[combined.Length - nonce.Length - tag.Length];
        
        Buffer.BlockCopy(combined, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(combined, nonce.Length, tag, 0, tag.Length);
        Buffer.BlockCopy(combined, nonce.Length + tag.Length, ciphertext, 0, ciphertext.Length);
        
        byte[] plaintextBytes = DecryptAesGcm(ciphertext, nonce, tag, key);
        
        return Encoding.UTF8.GetString(plaintextBytes);
    }
}

// Password hashing with ASP.NET Core Identity's hasher
public class PasswordHasher
{
    private readonly Microsoft.AspNetCore.Identity.PasswordHasher<string> _hasher;
    
    public PasswordHasher()
    {
        _hasher = new Microsoft.AspNetCore.Identity.PasswordHasher<string>();
    }
    
    public string HashPassword(string password)
    {
        return _hasher.HashPassword(null, password);
    }
    
    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        var result = _hasher.VerifyHashedPassword(null, hashedPassword, providedPassword);
        return result == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success;
    }
}
```

## Common Cryptography Pitfalls

1. **Insecure Key Generation**
   - Using predictable keys or passwords
   - Insufficient key length
   - Improper key derivation from passwords

2. **Improper Random Number Generation**
   - Using Math.random() or similar non-cryptographic RNGs
   - Seeding randomness with predictable values
   - Not using platform-specific secure random functions

3. **Insecure Mode of Operation**
   - Using ECB mode which doesn't hide data patterns
   - Using CBC without proper padding and IV handling
   - Using stream ciphers (e.g., RC4) which are known to be weak

4. **Lack of Authentication**
   - Using encryption without integrity verification
   - Not using an HMAC or authenticated encryption mode

5. **Poor Key Management**
   - Storing keys in plaintext
   - Embedding keys in source code
   - Not rotating keys regularly
   - Not securing key storage

## Best Practices for Specific Use Cases

### Secure Data at Rest

1. Use full-disk encryption when possible
2. For file encryption, use authenticated encryption
3. For database field encryption, consider using format-preserving encryption
4. Always encrypt sensitive data before storing it

### Secure Data in Transit

1. Always use TLS/HTTPS for network communications
2. Use TLS 1.3 or at minimum TLS 1.2 with secure cipher suites
3. Implement certificate pinning for mobile and sensitive applications
4. Use proper certificate validation

### Secure Key Exchange

1. Use established protocols like Diffie-Hellman key exchange
2. For web applications, consider using the Web Crypto API
3. Use forward secrecy when possible
4. For API keys, use proper authorization headers and avoid URL parameters

## Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards and Guidelines](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Cryptography Coding Standard](https://cryptocoding.net/index.php/Coding_rules)
- [Google Cloud Key Management Best Practices](https://cloud.google.com/kms/docs/best-practices)
- [AWS Key Management Service Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
