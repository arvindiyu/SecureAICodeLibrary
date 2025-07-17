# GitHub Security Instructions for GitHub Copilot

This directory contains GitHub Copilot custom instructions specific to GitHub security. These instructions guide Copilot to provide security-focused code suggestions for GitHub repositories, workflows, and integrations.

## Available Instructions

1. [GitHub Security Instructions](./github-security.md) - Comprehensive GitHub security instructions for GitHub Copilot

## Key GitHub Security Areas

The GitHub security instructions cover these key areas:

1. **Code Signing & Verification**
   - Git commit signing setup and configuration
   - Repository signature verification settings
   - Release artifact signing implementation
   - Keyless signing with OIDC implementation
   - Signature verification in CI/CD

2. **GitHub Actions Security**
   - Secure workflow configuration patterns
   - Principle of least privilege implementation
   - Actions version pinning best practices
   - Self-hosted runner security hardening
   - Secrets handling in workflows
   - OIDC for cloud provider authentication

3. **GitHub Apps & OAuth Security**
   - Secure GitHub App development patterns
   - App permission configuration best practices
   - Webhook security implementation
   - JWT authentication patterns
   - Installation token secure handling
   - OAuth scope configuration guidance
   - Secure authorization flow patterns

4. **Repository Security**
   - Branch protection rule configuration
   - Code owners setup and management
   - Status check requirement implementation
   - Security policy development
   - Repository secret management
   - Access control pattern implementation

5. **Security Scanning Integration**
   - CodeQL configuration and usage
   - Secret scanning setup and management
   - Dependency scanning implementation
   - Custom security tool integration
   - Automated security fix configuration
   - Supply chain security implementation

## Usage Instructions

### How to Use These Copilot Instructions

1. **Basic Setup**:
   - Copy the entire contents of [github-security.md](./github-security.md)
   - Add them to your GitHub Copilot custom instructions

2. **Combined with Other Instructions**:
   - These GitHub security instructions can be combined with other relevant security instructions
   - For CI/CD security, combine with general DevOps security instructions
   - For application security, combine with language-specific security instructions

3. **Customization**:
   - Tailor the instructions based on your specific GitHub security requirements
   - Add organization-specific security requirements or standards
   - Emphasize specific security areas most relevant to your repositories

4. **Effective Prompting**:
   - When working with Copilot, reference specific GitHub security requirements
   - Example: "Create a secure GitHub Actions workflow with CodeQL scanning"
   - Ask Copilot to follow GitHub security best practices when generating code

### Benefits

- Consistently secure GitHub configuration generation
- Implementation of GitHub security best practices
- Awareness of GitHub-specific vulnerabilities and mitigations
- Integration with GitHub security features and APIs
- Guidance on secure configuration of GitHub components
