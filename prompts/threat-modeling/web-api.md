# Secure Coding Prompt: Threat Modeling for Web & API

## Purpose

This prompt helps you perform comprehensive threat modeling for web applications and APIs. Use it to identify, evaluate, and mitigate potential security threats in your web and API-based systems before implementation or as part of security reviews.

## Web & API Threat Modeling Prompt

```
As a security architect, help me perform threat modeling for my [WEB APPLICATION/API] using a structured approach. 

System Information:
- Type: [Web Application, REST API, GraphQL API, etc.]
- Authentication: [OAuth, JWT, Session-based, API Keys, etc.]
- Data Sensitivity: [Public, Internal, Confidential, Regulated, etc.]
- User Types: [Unauthenticated, Regular Users, Admins, Partners, etc.]
- Technologies: [List key frameworks, languages and technologies]
- Infrastructure: [Cloud Provider, On-Premises, Hybrid, etc.]
- Compliance Requirements: [GDPR, HIPAA, PCI-DSS, SOC2, etc. if applicable]

Please provide a comprehensive threat model that includes:

1. System Overview:
   - Decompose the application into components
   - Identify trust boundaries
   - Map data flows across boundaries
   - Identify entry points and assets

2. Threat Identification (STRIDE):
   - Spoofing threats
   - Tampering threats
   - Repudiation threats
   - Information Disclosure threats
   - Denial of Service threats
   - Elevation of Privilege threats

3. Attack Surface Analysis:
   - API endpoints vulnerabilities
   - Authentication/authorization weaknesses
   - Data validation issues
   - Client-side vulnerabilities
   - Server-side vulnerabilities
   - Third-party integration risks

4. Risk Assessment:
   - Likelihood of each threat
   - Impact of successful exploitation
   - Risk calculation and prioritization

5. Mitigation Strategies:
   - Specific security controls for each threat
   - Implementation guidance for mitigations
   - Verification methods
   - Residual risk analysis

6. Security Requirements:
   - Specific security requirements for implementation
   - Security testing requirements
   - Monitoring and logging requirements

Please provide practical, actionable recommendations that consider the balance between security, functionality, and usability.
```

## Threat Modeling Components for Web & API

### 1. System Decomposition

#### Application Layers to Consider
- Client/Browser layer
- Presentation layer
- API layer
- Business logic layer
- Data access layer
- Database layer
- External service integration layer

#### Trust Boundaries to Identify
- Client-server boundary
- Authentication boundaries
- Authorization zones
- Internal-external system boundaries
- Multi-tenancy boundaries
- Cloud-provider boundaries

#### Data Flow Elements
- User inputs
- API requests/responses
- Database queries
- External service calls
- Authentication flows
- File uploads/downloads
- Data import/export operations

### 2. STRIDE Threat Categories for Web & API

#### Spoofing (Authentication)
- Session hijacking
- Credential theft
- Phishing attacks
- Account takeover
- Man-in-the-middle attacks
- Token forgery
- API key theft

#### Tampering (Integrity)
- Request forgery
- Response manipulation
- Parameter tampering
- Client-side storage manipulation
- Data corruption
- Malicious file uploads
- Supply chain compromise

#### Repudiation (Non-repudiation)
- Insufficient logging
- Log tampering
- Transaction denial
- Timestamp manipulation
- Audit trail gaps
- Missing non-repudiation controls
- Anonymous actions

#### Information Disclosure (Confidentiality)
- Sensitive data exposure
- Directory traversal
- Path disclosure
- Error message leakage
- API documentation exposure
- Metadata leakage
- Cache leaks
- Insecure direct object references

#### Denial of Service (Availability)
- Resource exhaustion
- API flooding
- Distributed DoS
- Logic-based attacks (CPU/memory intensive operations)
- Database connection pool exhaustion
- Storage depletion
- Regex DoS (ReDoS)

#### Elevation of Privilege (Authorization)
- Broken access control
- Role escalation
- Horizontal privilege escalation
- Vertical privilege escalation
- Missing function level authorization
- Insecure direct object references
- JWT/token tampering

### 3. Web & API Specific Attack Vectors

#### API-Specific Attack Vectors
- Broken object level authorization
- Broken authentication
- Excessive data exposure
- Lack of resources & rate limiting
- Broken function level authorization
- Mass assignment
- Security misconfiguration
- Injection
- Improper assets management
- Insufficient logging & monitoring

#### Web-Specific Attack Vectors
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Clickjacking
- Open redirects
- Insecure CORS configuration
- DOM-based vulnerabilities
- Client-side storage vulnerabilities
- Third-party JavaScript risks
- Content Security Policy bypass

#### Authentication & Authorization Weaknesses
- Insecure credential storage
- Weak password policies
- Missing MFA
- Insecure session management
- Token handling vulnerabilities
- OAuth/OIDC implementation flaws
- Authorization bypasses
- Insecure direct object references

### 4. Risk Assessment Framework

#### Likelihood Factors
- Ease of exploitation
- Technical skills required
- Authentication needed
- User interaction required
- Exploit availability
- Attack vector exposure

#### Impact Factors
- Data sensitivity
- System criticality
- Number of affected users
- Business impact
- Regulatory/compliance impact
- Reputational damage
- Financial loss

#### Risk Calculation Matrix
```
| Likelihood | Low Impact | Medium Impact | High Impact |
|------------|------------|---------------|-------------|
| High       | Medium     | High          | Critical    |
| Medium     | Low        | Medium        | High        |
| Low        | Low        | Low           | Medium      |
```

### 5. Mitigation Strategies by Layer

#### Client-Side Mitigations
- Content Security Policy (CSP)
- Subresource Integrity (SRI)
- X-Frame-Options / Frame-ancestors
- Input validation
- Anti-CSRF tokens
- Secure cookie flags
- Browser cache controls

#### API Mitigations
- Authentication for all endpoints
- Resource-based authorization
- Rate limiting and throttling
- Input validation and sanitization
- Output encoding
- Proper HTTP methods and status codes
- Security headers

#### Server-Side Mitigations
- Parameterized queries
- Input validation and sanitization
- Secure error handling
- Proper logging and monitoring
- Secure session management
- Least privilege execution
- Defense in depth strategies

#### Data Storage Mitigations
- Data encryption at rest
- Secure backup procedures
- Data minimization
- Retention policies
- Access controls
- Database hardening
- Query parameterization

### 6. Security Requirements Documentation

#### Authentication Requirements
- Authentication mechanism specifications
- Password/credential policies
- MFA requirements
- Session management requirements
- Account recovery processes

#### Authorization Requirements
- Permission model details
- Role definitions and scoping
- Data ownership rules
- Cross-tenant isolation requirements
- API-specific authorization rules

#### Data Protection Requirements
- Classification scheme
- Encryption requirements
- Data handling procedures
- Privacy compliance requirements
- Data retention requirements

#### Logging & Monitoring Requirements
- Events to be logged
- Log storage requirements
- Alerting thresholds
- Incident response procedures
- Compliance reporting requirements

## Example: API Threat Model Output

```
# Threat Model: Customer Management API

## System Overview

### Components:
- Authentication Service (OAuth 2.0 with JWT)
- Customer API Gateway
- Customer Microservice
- Billing Integration Service
- Customer Database (PostgreSQL)

### Trust Boundaries:
1. Client-API Gateway (External)
2. API Gateway-Authentication Service (Internal)
3. API Gateway-Customer Microservice (Internal)
4. Customer Microservice-Database (Internal)
5. Customer Microservice-Billing Service (Partner)

### Key Assets:
- Customer PII (High Sensitivity)
- Authentication Credentials (High Sensitivity)
- Billing Information (High Sensitivity)
- Usage Analytics (Medium Sensitivity)

## Threat Analysis (STRIDE)

### Spoofing Threats:
1. **JWT Token Theft** (High Risk)
   - Attacker steals JWT to impersonate legitimate user
   - Mitigation: Short token expiry, secure token storage, refresh token rotation

2. **API Key Compromise** (High Risk)
   - Partner API keys exposed or stolen
   - Mitigation: Key rotation, IP restriction, usage monitoring

### Tampering Threats:
1. **Request Manipulation** (Medium Risk)
   - Modified API requests to manipulate data
   - Mitigation: Input validation, integrity checks, proper authorization

2. **JWT Token Tampering** (Medium Risk)
   - Modification of JWT claims to gain privileges
   - Mitigation: Proper signature validation, use RS256 instead of HS256

### Repudiation Threats:
1. **Customer Data Change Disputes** (Medium Risk)
   - Users denying making changes to their data
   - Mitigation: Comprehensive audit logging, timestamps, user-agent recording

2. **Administrative Action Denial** (High Risk)
   - Administrators denying making system changes
   - Mitigation: Admin action logging, approval workflows, separation of duties

### Information Disclosure Threats:
1. **Excessive Data Exposure** (High Risk)
   - API returns excessive user data
   - Mitigation: Response filtering, field-level authorization

2. **Error Message Leakage** (Medium Risk)
   - Detailed errors expose system information
   - Mitigation: Generic error messages, proper exception handling

### Denial of Service Threats:
1. **API Flooding** (Medium Risk)
   - Overwhelming API with requests
   - Mitigation: Rate limiting, captcha for registration, API quotas

2. **Resource-Intensive Queries** (Medium Risk)
   - Complex queries consuming excessive resources
   - Mitigation: Query timeouts, pagination, result limiting

### Elevation of Privilege Threats:
1. **Broken Function Authorization** (Critical Risk)
   - Missing checks allowing access to unauthorized functions
   - Mitigation: Function-level authorization, API gateway policies

2. **Horizontal Privilege Escalation** (High Risk)
   - Accessing other customers' data by ID manipulation
   - Mitigation: Contextual access controls, UUID instead of sequential IDs

## Risk Assessment

| Threat | Likelihood | Impact | Risk Level |
|--------|------------|--------|------------|
| JWT Token Theft | Medium | High | High |
| API Key Compromise | Medium | High | High |
| Request Manipulation | Medium | Medium | Medium |
| JWT Token Tampering | Low | High | Medium |
| Customer Data Change Disputes | Medium | Medium | Medium |
| Administrative Action Denial | Low | High | Medium |
| Excessive Data Exposure | High | High | Critical |
| Error Message Leakage | High | Low | Medium |
| API Flooding | High | Medium | High |
| Resource-Intensive Queries | Medium | Medium | Medium |
| Broken Function Authorization | Medium | High | High |
| Horizontal Privilege Escalation | Medium | High | High |

## Mitigation Strategies

### Authentication & Authorization
1. Implement proper OAuth 2.0 flow with PKCE for SPA clients
2. Use short-lived JWTs (15 min) with refresh token rotation
3. Implement role-based and attribute-based access control
4. Enforce MFA for administrative actions
5. Implement contextual authorization for all data access

### API Security
1. Implement rate limiting at API Gateway (per user, IP, and endpoint)
2. Use API keys with proper restrictions for partner access
3. Validate all input against strict schemas (JSON Schema)
4. Implement proper HTTP response codes and error handling
5. Implement field-level authorization for all responses

### Data Protection
1. Encrypt sensitive PII at rest with field-level encryption
2. Implement proper data masking for non-essential PII exposure
3. Implement database connection encryption and certificate validation
4. Apply least privilege to database accounts
5. Implement proper data retention and purging policies

### Logging & Monitoring
1. Log all authentication events, successes and failures
2. Log all administrative actions with before/after states
3. Log all access to sensitive customer data
4. Implement real-time alerting for suspicious patterns
5. Store logs securely with tamper-evident mechanisms

## Security Requirements

1. All API endpoints must require authentication except documentation
2. All endpoints must validate authorization contextually
3. All customer data access must be logged with user context
4. All API responses must be filtered based on user permissions
5. Rate limiting must be applied to all authentication endpoints
6. All PII must be encrypted at rest and in transit
7. All errors must be logged but sanitized in responses
8. Administrative functions must require stepped-up authentication
9. All API calls must use TLS 1.2+ with secure cipher suites
```

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Web Application Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft Threat Modeling Tool](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [NIST SP 800-95 Guide to Secure Web Services](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-95.pdf)
