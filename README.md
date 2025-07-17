# Secure Code Library

A comprehensive collection of secure coding prompts, guidelines, and Copilot custom instructions for various programming languages, frameworks, and security methodologies.

## Repository Structure

This repository is organized into the following main sections:

1. **Secure Coding Prompts** - Located in the `prompts` directory, organized by category
2. **Copilot Custom Instructions** - Located in the `.github/copilot` directory, organized by category
3. **General Security Guidelines** - Located in the `guidelines` directory

## Categories

### Code Security
- Language Agnostic Secure Coding
- Secure Developer Assistant

## General Security Frameworks
- OWASP Top 10 (Web)
- OWASP API Top 10
- OWASP Top 10 for LLM
- Database Security
- Threat Modeling
- STRIDE Framework
- PASTA Framework

### API Security
- Secure API Design
- API Authentication
- API Authorization
- API Data Validation
- API Rate Limiting

### Cloud Security
- AWS Security Configuration
- GCP Security Configuration
- Azure Security Configuration
- Terraform Security

### Code — Infra & Testing
- Docker & Docker-Compose
- GitLab CI
- Ansible
- IaC (Terraform — AWS, Azure, GCP)
- OIDC / OAuth 2 (Auth0, IdentityServer, Okta)
- Secure MCP Builder
- OAuth 2 / OIDC Assistant
- WebAssembly Security
- GitHub Security
  - Code Signing & Verification
  - Secure GitHub Actions Workflows
  - GitHub Apps Security
  - OAuth Apps Configuration
  - Repository Security Settings
  - Branch Protection Rules
  - Dependabot Configuration
  - Security Scanning Integration

### Secrets Management
- Secrets Detection Assistant
- Secrets Rotation Strategy Advisor
- Secrets Vault Configuration Guide
- Tokenization Strategy Designer
- Least-Privilege Policy Author
- Credential Hygiene Checklist

### Threat Modeling
- Threat-Model : General
- Threat-Model : Web & API
- Threat-Model : Diagram Generator

### Content Verification
- Content Training Review
- RAG Live Content Review

### Validation
- Dynamic Test-Plan Generator
- Static Analysis Rule-Set Designer
- SAST/DAST Tuning Assistant
- Regression Test Harness
- API Fuzzing Guide
- Hard-Mode Pentest Scenario Builder


### Code — Client-Side
- Angular
- Fresh
- Next.js
- Svelte
- Vue.js

### Code — Mobile
- Android (Java, Kotlin)
- iOS (Swift, SwiftUI, Objective-C)
- React Native
- Electron Mobile
- Common Mobile Security (Platform-agnostic)

### Code — Backend Frameworks
- Azure Functions
- FastAPI
- Flask
- Google Cloud Functions
- Go (Echo, Gin)
- Java (Spring Boot, MVC)
- .NET (ASP.NET Core)
- Node (JS / TypeScript)
- PHP (Laravel, Symfony, General)
- Python (SQLAlchemy, PySpark)
- Ruby on Rails
- Rust (Axum, General)
- Unity (Rules)

### Workforce Enablement
- Secure-Coding Mentor Bot
- Lunch-and-Learn Playbook
- Developer On-Ramp for Secure Coding
- AppSec Champion Program Kit
- Pair-Programming Drills
- Brown-Bag Talks Catalog
- Executive Briefing Deck
- Incident-Response Tabletop Scenario
- Gamified Bug-Fix Race
- Secure SDLC Maturity Self-Assessment
- DevSecOps Roadmap Planner


## Usage Standard Operating Procedure (SOP)

### For Developers:

1. **Identify Your Technology**: Navigate to the relevant section for your technology stack or security concern.
   - Start with the most specific prompt for your technology (e.g., Android Kotlin, iOS Swift)
   - Also review common security principles that apply across platforms

2. **Apply in Development**:
   - Use the prompts to guide your implementation of security features
   - Follow the provided code examples and adapt them to your application
   - Refer to the security testing guidelines to verify your implementation

3. **Comprehensive Security Review**:
   - Use threat modeling prompts to identify potential security risks
   - Apply security framework guidance (OWASP Top 10, STRIDE, etc.)
   - Incorporate security verification as part of your development process

### For Copilot Users:

1. **Configure Custom Instructions**:
   - Copy the relevant custom instructions from the `.github/copilot` directory
   - Apply these instructions to your Copilot configuration
   - Combine multiple instruction sets for projects using multiple technologies

2. **Using with Copilot**:
   - Reference the secure coding principles in your prompts to Copilot
   - Ask Copilot to follow specific security guidelines from this repository
   - Verify generated code against the security checklists provided

3. **Continuous Improvement**:
   - Update your custom instructions as new versions become available
   - Provide feedback on instruction effectiveness
   - Combine with secure coding prompts for comprehensive coverage

### For Security Teams:

1. **Training and Awareness**:
   - Use the general guidelines as references for security reviews
   - Create training materials based on the security frameworks provided
   - Develop security champions programs using the workforce enablement content

2. **Security Reviews and Assessments**:
   - Apply the security verification guidelines during code reviews
   - Use the threat modeling prompts to facilitate security discussions
   - Leverage the testing guides for security assessments

3. **Policy Development**:
   - Use these resources to develop secure coding standards
   - Map organizational requirements to established security frameworks
   - Create custom security guidelines based on these templates

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This repository is licensed under the MIT License - see the LICENSE file for details.
