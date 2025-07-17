# GitHub Security Prompts

This directory contains security prompts specific to GitHub repositories, workflows, and integrations. These prompts focus on security best practices for GitHub-related development workflows and infrastructure.

## Available Prompts

1. [GitHub Security Best Practices](./github-security.md) - Comprehensive GitHub security guidelines and code examples

## Key GitHub Security Areas

The GitHub security prompts cover these key areas:

1. **Code Signing & Verification**
   - Git commit signing with GPG keys
   - Repository signature verification
   - Release artifact signing
   - Keyless signing with OIDC
   - Trusted contributor verification

2. **GitHub Actions Security**
   - Secure workflow configuration
   - Principle of least privilege implementation
   - Actions version pinning
   - Self-hosted runner security
   - Secrets handling in workflows
   - OIDC for cloud provider authentication

3. **GitHub Apps Security**
   - Secure GitHub App development
   - App permission configuration
   - Webhook security
   - JWT authentication
   - Installation token handling

4. **OAuth Apps Security**
   - Secure OAuth scope configuration
   - Authorization flow security
   - Token storage and rotation
   - PKCE implementation
   - Security review process

5. **Repository Security**
   - Branch protection rules
   - Code owners configuration
   - Status check requirements
   - Security policy setup
   - Repository secret management
   - Access control best practices

6. **Security Scanning Integration**
   - CodeQL integration
   - Secret scanning setup
   - Dependency scanning
   - Custom security tool integration
   - Automated security fixes
   - Supply chain security measures

## Usage Instructions

### For Developers

1. **Review Security Fundamentals First**
   - Understand the GitHub security model and capabilities
   - Identify which security controls are relevant to your repositories

2. **Apply GitHub-Specific Security Controls**
   - Use the [GitHub Security Best Practices](./github-security.md) guide for implementation details
   - Adapt the configuration examples to your repositories
   - Follow GitHub-specific security recommendations

3. **Integration with Development Process**
   - Incorporate GitHub security checks into your CI/CD workflows
   - Use the provided examples as templates for your implementation
   - Apply the security guidelines during repository and workflow setup

### For DevOps and Security Teams

1. **Security Assessment**
   - Use the security guidelines as a checklist for GitHub repository reviews
   - Verify that GitHub-specific security controls are properly implemented
   - Check for proper usage of GitHub security features

2. **Policy Implementation**
   - Implement organizational GitHub security policies
   - Use configuration-as-code to enforce security standards
   - Create templates for secure GitHub workflows and settings

## Related Resources

1. [GitHub Security Documentation](https://docs.github.com/en/code-security)
2. [GitHub Advanced Security](https://github.com/features/security)
3. [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides)
4. [OWASP GitHub Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Github_Security_Cheat_Sheet.html)
