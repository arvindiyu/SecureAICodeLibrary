# Secure Coding Prompt: Secrets Detection Assistant

## Purpose

This prompt helps you identify, manage, and remediate exposed secrets in your codebase. Use this to detect hardcoded credentials, API keys, tokens, and other sensitive information that should not be stored in code repositories.

## Secrets Detection Assistant Prompt

```
As a Secrets Detection Assistant, help me identify and remediate potential secrets and sensitive information in my codebase. 

I need your assistance to:

1. Scan the [FILE/DIRECTORY/CODEBASE] for potential secrets or credentials
2. Identify any of the following security issues:
   - Hardcoded API keys, tokens, or credentials
   - Private keys or certificates
   - Connection strings with embedded credentials
   - Hardcoded passwords or passphrases
   - Authentication tokens or session identifiers
   - Other sensitive information that should be externalized

For each detected issue:
1. Explain why it's a security concern
2. Suggest the appropriate method to externalize or secure the secret
3. Provide code examples showing the secure implementation
4. Recommend appropriate secret management solutions for my environment

Technical context:
- Language/Framework: [LANGUAGE/FRAMEWORK]
- Environment: [CLOUD PROVIDER/ON-PREMISE]
- CI/CD: [CI/CD PLATFORM]
- Current secret storage: [HOW SECRETS ARE CURRENTLY STORED]

Ensure your recommendations follow security best practices and industry standards for secret management.
```

## Secret Detection Patterns

The following patterns should be used to identify potential secrets in code:

### API Keys and Tokens

- **AWS**: `AKIA[0-9A-Z]{16}`
- **GitHub**: `gh[opsu]_[0-9a-zA-Z]{36}`
- **Google API**: `AIza[0-9A-Za-z\\-_]{35}`
- **Firebase**: `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`
- **Stripe**: `sk_live_[0-9a-zA-Z]{24}`
- **Generic API Key**: `[a-z0-9]{32}`

### Database Connection Strings

- **MongoDB**: `mongodb(\+srv)?://[^:]+:[^@]+@[^/]+/[^?]+(\?.*)?`
- **MySQL**: `mysql://[^:]+:[^@]+@[^/]+/[^?]+(\?.*)?`
- **PostgreSQL**: `postgres(ql)?://[^:]+:[^@]+@[^/]+/[^?]+(\?.*)?`
- **MSSQL**: `Server=.+;Database=.+;User Id=.+;Password=.+;`
- **Oracle**: `jdbc:oracle:thin:@//[^:]+:[^:]+:.+`

### Private Keys and Certificates

- **Private Key**: `-----BEGIN( RSA)? PRIVATE KEY-----`
- **SSH Key**: `-----BEGIN( OPENSSH)? PRIVATE KEY-----`
- **PGP Private Key**: `-----BEGIN PGP PRIVATE KEY BLOCK-----`
- **Certificate**: `-----BEGIN CERTIFICATE-----`

### Authentication Credentials

- **Basic Auth**: `Authorization: Basic [a-zA-Z0-9+/=]+`
- **Bearer Token**: `Authorization: Bearer [a-zA-Z0-9._\-]+`
- **Generic Password**: `password\s*=\s*['"][^'"]+['"]`

## Remediation Strategies

### Environment Variables

```javascript
// BAD: Hardcoded API key
const apiKey = "sk_live_abcd1234efgh5678ijkl9012";

// GOOD: Use environment variable
const apiKey = process.env.STRIPE_API_KEY;
```

### Configuration Files (excluded from source control)

```javascript
// BAD: Connection string in code
const dbConnection = "postgres://user:password123@localhost:5432/mydb";

// GOOD: Load from configuration file
import config from './config';
const dbConnection = config.database.connectionString;

// Ensure config.js is in .gitignore
```

### Secret Management Services

```javascript
// BAD: Hardcoded credentials
const credentials = {
  username: "admin",
  password: "super_secure_password"
};

// GOOD: Using a secret manager (AWS Secrets Manager example)
const { SecretsManager } = require('aws-sdk');
const secretsManager = new SecretsManager();

async function getCredentials() {
  const response = await secretsManager.getSecretValue({
    SecretId: 'my-service-credentials'
  }).promise();
  
  return JSON.parse(response.SecretString);
}
```

### Infrastructure as Code

```yaml
# BAD: Hardcoded secrets in IaC
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
data:
  db-password: cGFzc3dvcmQxMjM=  # base64 encoded "password123"

# GOOD: Reference external secret management
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
  data:
    - secretKey: db-password
      remoteRef:
        key: database/credentials
        property: password
```

## Secret Management Solutions

### Cloud Provider Solutions

- **AWS**: AWS Secrets Manager, Parameter Store
- **Azure**: Azure Key Vault
- **Google Cloud**: Secret Manager
- **IBM Cloud**: Secrets Manager

### Self-Hosted Solutions

- **HashiCorp Vault**: Comprehensive secrets management
- **Keywhiz**: File-based secret distribution service
- **Knox**: Key management service built by Pinterest

### Developer Tools

- **git-secrets**: Prevents committing secrets to Git repositories
- **detect-secrets**: Detects secrets within code by identifying high-entropy strings
- **truffleHog**: Searches through Git repositories for secrets
- **GitGuardian**: Automated secrets detection and remediation

## Best Practices for Secret Management

1. **Never commit secrets** to source control
2. **Rotate credentials** regularly
3. **Use least privilege** access for service accounts
4. **Audit and monitor** secret access
5. **Implement secret versioning** for secure rotation
6. **Set expiration dates** on secrets when possible
7. **Use different secrets** across environments
8. **Encrypt secrets** at rest and in transit
9. **Implement secret scanning** in CI/CD pipelines
10. **Properly sanitize logs** to avoid leaking secrets

## Example CI/CD Integration

### GitHub Actions Secret Scanning

```yaml
name: Secret Scanning

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  detect-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Detect secrets
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab CI Secret Scanning

```yaml
secret_detection:
  stage: test
  image: 
    name: "registry.gitlab.com/gitlab-org/security-products/secret-detection:3"
    entrypoint: [""]
  script:
    - /analyzer run
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
```

## Secret Rotation Strategy

1. **Create new secret**: Generate a new credential without disrupting service
2. **Deploy new secret**: Update applications to use the new credential
3. **Verify functionality**: Ensure the application works with the new secret
4. **Revoke old secret**: Once all services are using the new secret, disable the old one

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST Guidelines for Managing Secrets](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf)
- [CIS Controls for Secret Management](https://www.cisecurity.org/controls/)
