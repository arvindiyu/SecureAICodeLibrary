# GitHub Security Best Practices

## Prompt

As a GitHub Security Specialist, help me implement secure practices for my GitHub repositories, workflows, and integrations. Consider these security aspects when providing guidance:

### Code Signing & Verification

- Implement Git commit signing with GPG keys
- Configure repository to require signed commits
- Set up CI/CD verification of signature authenticity
- Establish trusted contributor verification process
- Implement release artifact signing
- Set up Gitsign with keyless signing using OpenID Connect

### Secure GitHub Actions Workflows

- Implement principle of least privilege in workflow permissions
- Use trusted and pinned action versions (avoid `@master` references)
- Securely handle secrets in GitHub Actions
- Implement proper GITHUB_TOKEN permission scoping
- Implement workflow security scanning
- Use OpenID Connect for cloud provider authentication
- Implement security hardening for self-hosted runners
- Configure proper job isolation and cleanup

### GitHub Apps Security

- Implement secure GitHub App development practices
- Configure proper app permissions using least privilege
- Implement secure webhook handling
- Use JWT authentication properly
- Store installation tokens securely
- Implement proper OAuth scopes for GitHub Apps
- Configure security scanning for GitHub App code

### OAuth Apps Security

- Configure minimal OAuth scopes
- Implement secure authorization flow
- Secure token storage and handling
- Implement proper token rotation
- Configure user permission review process
- Implement PKCE for authorization code flow
- Use state parameters to prevent CSRF attacks

### Repository Security Settings

- Configure appropriate branch protection rules
- Set up code owners for security-critical code
- Configure required status checks before merging
- Implement security policies (SECURITY.md)
- Configure dependency scanning and Dependabot
- Implement repository secret scanning
- Configure proper code access permissions
- Set up security advisories and vulnerability reporting

### Security Scanning Integration

- Set up CodeQL analysis in CI/CD pipeline
- Configure secret scanning for repositories
- Implement dependency vulnerability scanning
- Set up custom security scanning tools
- Configure security issue tracking and remediation
- Implement security metrics and reporting
- Configure automated security fixes
- Implement supply chain security measures

## Example Implementation: Secure GitHub Actions Workflow

```yaml
name: Secure CI Pipeline

# Only trigger on specific events with limited scope
on:
  push:
    branches: [ main ]
    paths-ignore:
      - '**.md'
      - 'docs/**'
  pull_request:
    branches: [ main ]
    paths-ignore:
      - '**.md'
      - 'docs/**'

jobs:
  security-scan:
    # Define permissions explicitly following principle of least privilege
    permissions:
      contents: read
      security-events: write
      actions: none
      checks: write
      
    runs-on: ubuntu-latest
    
    steps:
      # Pin to a specific SHA for security
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          # Full history for proper scanning
          fetch-depth: 0
          # Verify commit signatures
          show-progress: false
      
      # Verify commit signatures
      - name: Verify commit signatures
        run: |
          git log --show-signature -n 10
          # Additional verification logic can be added here
      
      # Use pinned version with SHA for critical security actions
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript, python
          queries: security-and-quality
          
      # Secret scanning with pinned version
      - name: Run secret scanning
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
          
      # Dependency security scanning
      - name: Run Dependency Review
        uses: actions/dependency-review-action@v2
        with:
          fail-on-severity: moderate
          
      # Software composition analysis
      - name: Run OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'my-project'
          path: '.'
          format: 'HTML'
          out: 'reports'
          args: >
            --failOnCVSS 7
            --enableExperimental
            
      # Upload scan results to GitHub Security tab
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/dependency-check-report.sarif
          category: 'dependency-check'
```

## Example Implementation: Branch Protection Configuration

This example shows how to configure branch protection rules using the GitHub API:

```javascript
// Using GitHub REST API with Octokit
const { Octokit } = require("@octokit/rest");
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

async function configureBranchProtection() {
  try {
    await octokit.repos.updateBranchProtection({
      owner: "your-org",
      repo: "your-repo",
      branch: "main",
      required_status_checks: {
        strict: true,
        contexts: ["security-scan", "ci-tests", "code-coverage"],
      },
      enforce_admins: true,
      required_pull_request_reviews: {
        dismiss_stale_reviews: true,
        require_code_owner_reviews: true,
        required_approving_review_count: 2,
        require_last_push_approval: true,
      },
      restrictions: null,
      required_linear_history: true,
      allow_force_pushes: false,
      allow_deletions: false,
      required_conversation_resolution: true,
      require_signed_commits: true,
    });
    
    console.log("Branch protection rules configured successfully");
  } catch (error) {
    console.error("Error configuring branch protection:", error);
  }
}

configureBranchProtection();
```

## Example Implementation: Git Commit Signing Setup

This guide helps users set up Git commit signing:

```bash
# Generate a new GPG key
gpg --full-generate-key

# List GPG keys to find ID
gpg --list-secret-keys --keyid-format=long

# Export the public key
gpg --armor --export YOUR_KEY_ID

# Configure Git to use this key
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# For keyless signing with Gitsign
# Install Gitsign
brew install sigstore/tap/gitsign

# Configure Git to use Gitsign
git config --global gpg.format ssh
git config --global gpg.ssh.program gitsign
git config --global commit.gpgsign true
```

## Key Security Considerations

1. **Principle of Least Privilege**: Always assign the minimum permissions needed for GitHub tokens, apps, and workflows.

2. **Version Pinning**: Pin to specific versions (preferably with SHA) of GitHub Actions to prevent supply chain attacks.

3. **Secrets Management**: Never store secrets in code, use GitHub Secrets with proper access controls.

4. **Identity Verification**: Use commit signing to verify the identity of contributors.

5. **Dependency Management**: Regularly scan and update dependencies to address vulnerabilities.

6. **Automation**: Implement automated security scanning in CI/CD pipelines.

7. **Access Control**: Implement proper branch protection and code ownership rules.

8. **Token Security**: Implement proper token handling, rotation, and scope limitation.

9. **Supply Chain Security**: Verify the integrity of dependencies and actions used in workflows.

10. **Incident Response**: Have clear procedures for addressing security issues found in repositories.

## Additional Resources

1. [GitHub Security Documentation](https://docs.github.com/en/code-security)
2. [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides)
3. [GitHub Advanced Security Features](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
4. [Securing GitHub Actions](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
5. [OWASP GitHub Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Github_Security_Cheat_Sheet.html)
