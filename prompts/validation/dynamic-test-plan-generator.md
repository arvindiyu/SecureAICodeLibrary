# Secure Coding Prompt: Dynamic Test-Plan Generator

## Purpose

This prompt guides you in creating comprehensive and security-focused test plans for applications, services, and systems. Use this prompt to generate dynamic test plans that cover functional requirements, security vulnerabilities, edge cases, and compliance concerns.

## Dynamic Test-Plan Generator Prompt

```
As a security-focused test engineer, help me create a comprehensive test plan for [APPLICATION/SYSTEM NAME].

System information:
1. Description: [Brief description of the application/system]
2. Architecture: [Monolith, microservices, client-server, etc.]
3. Technology stack: [Programming languages, frameworks, databases, etc.]
4. Target environments: [Development, QA, staging, production]
5. Security requirements: [Authentication, authorization, data protection, compliance needs]
6. Critical functionality: [Key features or workflows that need thorough testing]

Generate a comprehensive test plan that includes:
1. Test objectives and scope
2. Test strategy (types of testing required)
3. Security testing approach
4. Test scenarios with prioritization
5. Test data requirements with security considerations
6. Environment requirements
7. Test execution schedule
8. Defect management process
9. Reporting approach
10. Risks and mitigations

For security testing, include specific test cases that address:
1. Authentication and authorization vulnerabilities
2. Input validation and sanitization
3. Session management
4. Data protection and privacy
5. Injection attacks
6. Cross-site scripting and request forgery
7. API security
8. Secure configuration
9. Error handling and logging
10. Third-party component security

Format the output as a structured test plan document with clear sections, detailed test scenarios, and security-focused test cases.
```

## Test Plan Components

### 1. Test Objectives and Scope

Define the purpose and boundaries of your testing effort:
- Clear statement of testing goals
- Features and functionality in scope
- Explicit out-of-scope items
- Entry and exit criteria
- Assumptions and constraints

### 2. Test Strategy

Select appropriate testing methodologies:
- Functional testing
- Security testing
- Performance testing
- Usability testing
- Integration testing
- Regression testing
- Automated vs. manual testing ratio
- Test data strategy

### 3. Security Testing Approach

Detail security-specific testing methodologies:
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Interactive Application Security Testing (IAST)
- API security testing
- Penetration testing
- Threat modeling integration
- Security code review process

### 4. Test Scenarios with Prioritization

Develop comprehensive test scenarios:
- Critical path testing
- Security-focused scenarios
- Edge case scenarios
- Integration points
- Error handling paths
- Priority levels (Critical, High, Medium, Low)

### 5. Test Data Requirements

Define data needs with security in mind:
- Sensitive data handling approach
- Test data creation methods
- Data anonymization techniques
- Production data usage policies
- Data cleanup procedures

### 6. Environment Requirements

Specify testing infrastructure needs:
- Environment specifications
- Security configuration requirements
- Network isolation needs
- Tool requirements
- Access control specifications

### 7. Test Execution Schedule

Create a timeline for testing activities:
- Test cycles and phases
- Security testing integration points
- Dependencies and blockers
- Resource allocation
- Reporting milestones

### 8. Defect Management Process

Establish bug tracking and remediation procedures:
- Defect categorization system
- Security vulnerability classification
- Severity and priority definitions
- Escalation paths
- Verification process

### 9. Reporting Approach

Define how test results will be communicated:
- Status reporting frequency
- Security findings communication
- Metrics and KPIs
- Executive summaries
- Compliance reporting

### 10. Risks and Mitigations

Identify potential testing challenges:
- Schedule risks
- Resource constraints
- Technical limitations
- Security testing limitations
- Contingency plans

## Example Implementation: Web Application Test Plan

### Test Plan for E-commerce Web Application

#### 1. Test Objectives and Scope

**Objectives:**
- Validate core e-commerce functionality works as designed
- Ensure the application is secure against OWASP Top 10 vulnerabilities
- Verify compliance with PCI DSS requirements
- Validate application performance under expected load
- Ensure proper data protection for customer information

**In Scope:**
- User registration and authentication
- Product catalog and search functionality
- Shopping cart and checkout process
- Payment processing integration
- Order management system
- Customer account management
- Admin dashboard

**Out of Scope:**
- Third-party integrations beyond defined APIs
- Physical security of hosting infrastructure
- Full PCI DSS audit (limited to application controls)
- Performance testing beyond 2× expected peak load

**Entry Criteria:**
- Application deployed to test environment
- Test data loaded and verified
- Test environment configured to match production security controls
- All dependencies and services operational
- Security scanning tools configured

**Exit Criteria:**
- All critical and high-priority test cases executed
- Zero open critical or high security vulnerabilities
- All payment flows verified secure and compliant
- Performance meets defined SLAs
- Regression test suite passes at 100%

#### 2. Test Strategy

**Testing Types:**

| Test Type | Approach | Tools | Ownership |
|-----------|----------|-------|-----------|
| Functional Testing | Manual and automated | Selenium, Cypress | QA Team |
| Security Testing | Automated scanning and manual penetration testing | OWASP ZAP, Burp Suite | Security Team |
| Performance Testing | Load and stress testing | JMeter, Gatling | Performance Team |
| API Testing | Automated with some manual verification | Postman, SoapUI | API Test Team |
| Usability Testing | Manual user journey validation | User feedback tools | UX Team |
| Accessibility Testing | Automated and manual review | axe, WAVE | Accessibility Team |

**Test Automation Strategy:**
- 80% of regression tests to be automated
- Security scanning integrated into CI/CD pipeline
- Daily automated smoke tests
- API contract testing automated

**Test Data Strategy:**
- Synthetic test data for most scenarios
- Anonymized production-like data for complex flows
- Secure handling of test credit card data
- Data refresh strategy for each test cycle

#### 3. Security Testing Approach

**Security Testing Methodology:**

| Testing Type | Description | Frequency | Tools |
|--------------|-------------|-----------|-------|
| SAST | Static code analysis | On every commit | SonarQube, Checkmarx |
| DAST | Dynamic testing of running application | Daily and pre-release | OWASP ZAP, Burp Suite |
| IAST | Runtime testing with instrumentation | Weekly | Contrast Security |
| Dependency Scanning | Check for vulnerable dependencies | Daily | OWASP Dependency Check, Snyk |
| Container Scanning | Scan container images | On image build | Trivy, Clair |
| Penetration Testing | Manual expert testing | Quarterly and major releases | Manual tools |
| Security Code Review | Manual review of security-critical code | For auth, payment, and admin features | Manual process |

**Security Testing Focus Areas:**
- Authentication mechanisms
- Session management
- Access control and authorization
- Input validation and output encoding
- Payment processing security
- Data protection and privacy
- API security
- Error handling and logging security
- Third-party component security
- Secure configuration

**Security Tools Integration:**
- Security scanners integrated into CI/CD pipeline
- Automated vulnerability reporting to issue tracker
- Security gates defined for deployment approval
- Regular security dashboard updates

#### 4. Test Scenarios with Prioritization

**Authentication and User Management:**

| ID | Test Scenario | Priority | Security Focus |
|----|---------------|----------|---------------|
| AUTH-001 | Verify user registration with valid data | High | Data validation |
| AUTH-002 | Verify password complexity requirements | Critical | Authentication security |
| AUTH-003 | Test account lockout after failed login attempts | Critical | Brute force protection |
| AUTH-004 | Verify password reset functionality | Critical | Account recovery security |
| AUTH-005 | Test multi-factor authentication | High | Authentication strength |
| AUTH-006 | Verify session timeout functionality | High | Session security |
| AUTH-007 | Test for session fixation vulnerabilities | Critical | Session security |
| AUTH-008 | Verify secure storage of authentication tokens | Critical | Data protection |

**Shopping Cart and Checkout:**

| ID | Test Scenario | Priority | Security Focus |
|----|---------------|----------|---------------|
| CART-001 | Add product to cart and verify totals | Critical | Functional integrity |
| CART-002 | Modify quantities and verify calculations | High | Input validation |
| CART-003 | Apply discount codes and verify pricing | High | Business logic security |
| CART-004 | Test checkout process with valid payment | Critical | Payment security |
| CART-005 | Verify address validation during checkout | Medium | Data validation |
| CART-006 | Test order submission with concurrent sessions | High | Race condition security |
| CART-007 | Verify payment information is not stored | Critical | PCI compliance |
| CART-008 | Test checkout with different payment methods | High | Payment integration security |

**Admin Functionality:**

| ID | Test Scenario | Priority | Security Focus |
|----|---------------|----------|---------------|
| ADMIN-001 | Verify admin login with strong authentication | Critical | Access control |
| ADMIN-002 | Test product creation and management | High | Input validation |
| ADMIN-003 | Verify order management functionality | High | Data integrity |
| ADMIN-004 | Test user management by admin | Critical | Privilege management |
| ADMIN-005 | Verify audit logging of admin actions | High | Accountability |
| ADMIN-006 | Test admin role permissions | Critical | Access control |
| ADMIN-007 | Verify secure access to reports and analytics | High | Data protection |
| ADMIN-008 | Test admin password policy enforcement | Critical | Authentication security |

#### 5. Security-Focused Test Cases

**Authentication Security:**

```
Test Case ID: SEC-AUTH-001
Title: Testing for authentication bypass
Priority: Critical
Description: Attempt to bypass authentication mechanisms
Preconditions: Application is running in test environment
Test Steps:
1. Attempt direct access to protected URLs without authentication
2. Modify session cookies to attempt session hijacking
3. Test for forced browsing to administrative functions
4. Attempt parameter tampering on login requests
5. Test for insecure "remember me" functionality
Expected Results:
- All authentication bypass attempts should be blocked
- Proper error messages shown without revealing system information
- Failed attempts logged with appropriate details
- Account lockout triggered after defined threshold
Security Focus: Authentication bypass, access control
```

**Injection Attacks:**

```
Test Case ID: SEC-INJ-001
Title: SQL Injection testing on input fields
Priority: Critical
Description: Test application for SQL injection vulnerabilities
Preconditions: Application is running with test database
Test Steps:
1. Identify all input fields that might interact with database
2. Test each field with common SQL injection payloads:
   a. ' OR '1'='1
   b. '; DROP TABLE users; --
   c. ' UNION SELECT username, password FROM users; --
3. Test URL parameters and API endpoints with injection payloads
4. Test for blind SQL injection using boolean conditions
5. Test for time-based SQL injection
Expected Results:
- Input validation should prevent SQL injection
- Parameterized queries should protect against injection
- No database errors exposed to users
- No unauthorized data access possible
- All injection attempts logged and flagged
Security Focus: Injection prevention, input validation
```

**Cross-Site Scripting (XSS):**

```
Test Case ID: SEC-XSS-001
Title: Testing for Cross-Site Scripting vulnerabilities
Priority: Critical
Description: Test application for XSS vulnerabilities in input/output fields
Preconditions: Application is running in test environment
Test Steps:
1. Identify all user input fields that output data back to pages
2. Test each field with common XSS payloads:
   a. <script>alert('XSS')</script>
   b. <img src="x" onerror="alert('XSS')">
   c. <body onload="alert('XSS')">
3. Test stored XSS in reviews, comments, and profile fields
4. Test reflected XSS in search, error messages, and URL parameters
5. Test for DOM-based XSS in client-side scripts
Expected Results:
- Input validation should sanitize dangerous input
- Output encoding should prevent script execution
- Content Security Policy should mitigate XSS attempts
- No JavaScript execution possible via injected content
Security Focus: XSS prevention, output encoding
```

**API Security:**

```
Test Case ID: SEC-API-001
Title: Testing API endpoint security
Priority: Critical
Description: Verify security controls on API endpoints
Preconditions: API documentation available, test accounts configured
Test Steps:
1. Test API authentication mechanisms:
   a. Missing authentication tokens
   b. Expired tokens
   c. Invalid tokens
   d. Tokens from different users
2. Test authorization controls:
   a. Access resources belonging to other users
   b. Attempt privilege escalation
   c. Test RBAC implementation
3. Test for injection in API parameters
4. Test rate limiting and anti-automation controls
5. Verify secure handling of sensitive data in responses
Expected Results:
- All unauthorized requests properly rejected
- Appropriate HTTP status codes returned (401, 403)
- Rate limiting prevents excessive requests
- No sensitive data leaked in responses
- Proper error handling without system information disclosure
Security Focus: API security, authorization
```

**Data Protection:**

```
Test Case ID: SEC-DATA-001
Title: Testing for sensitive data exposure
Priority: Critical
Description: Verify protection of sensitive customer data
Preconditions: Test accounts with profile data created
Test Steps:
1. Intercept all traffic using proxy tool (Burp Suite/ZAP)
2. Review all responses for sensitive data:
   a. Credit card numbers
   b. Authentication credentials
   c. Personal identifiable information
3. Check browser storage (localStorage, sessionStorage, cookies)
4. Verify data minimization in API responses
5. Test for caching of sensitive data
6. Check secure flag on sensitive cookies
Expected Results:
- All sensitive data transmitted over HTTPS
- No sensitive data cached in browser
- PII properly masked in logs and responses
- Secure flags set on authentication cookies
- No exposure of sensitive data in error messages
Security Focus: Data protection, privacy
```

#### 6. Test Data Requirements

**Test Data Categories:**

| Category | Data Type | Source | Security Considerations |
|----------|-----------|--------|------------------------|
| User Accounts | Synthetic | Generated | Secure storage of test credentials |
| Product Catalog | Copy of production | Exported | No security concerns |
| Payment Information | Test cards only | Payment processor | Use only official test card numbers |
| Customer Profiles | Synthetic | Generated | Use fake but realistic data |
| Order History | Synthetic | Generated | No real customer data |

**Sensitive Data Handling:**
- Test credit cards will use only official test numbers from payment processors
- PII data will be completely synthetic and randomly generated
- No production customer data will be used in testing environments
- Test data will be refreshed between major test cycles
- Database encryption applied to test environments matching production

#### 7. Environment Requirements

**Test Environments:**

| Environment | Purpose | Configuration | Data |
|-------------|---------|--------------|------|
| Development | Developer testing | Reduced security controls | Minimal test data |
| QA | Functional testing | Production-like | Full test dataset |
| Staging | Pre-production validation | Mirror of production | Sanitized copy of production |
| Security Test | Security-focused testing | Production security controls | Synthetic data |

**Security Configuration:**
- TLS 1.2+ enforced on all environments
- Web Application Firewall configured in monitoring mode
- Network segregation matching production
- Secrets management using vault technology
- Database encryption enabled
- Logging and monitoring configured

**Tools and Access:**
- OWASP ZAP and Burp Suite for security testing
- Selenium and Cypress for functional automation
- JMeter for performance testing
- Test account credentials managed in secure vault
- Environment access controlled via VPN and MFA

#### 8. Defect Management Process

**Defect Severity Classification:**

| Severity | Description | Response Time | Example |
|----------|-------------|---------------|---------|
| Critical | System unusable, security breach | Immediate | Authentication bypass |
| High | Major function affected, potential security issue | 24 hours | Payment calculation error |
| Medium | Minor function affected | 3 days | UI display issue |
| Low | Cosmetic or minor issue | 1 week | Typo in error message |

**Security Vulnerability Classification:**

| CVSS Score | Severity | Response Time | Example |
|------------|----------|---------------|---------|
| 9.0 - 10.0 | Critical | Immediate | Remote code execution |
| 7.0 - 8.9 | High | 24 hours | SQL injection |
| 4.0 - 6.9 | Medium | 72 hours | XSS vulnerability |
| 0.1 - 3.9 | Low | 1 week | Information disclosure |

**Defect Management Workflow:**
1. Defect identified and documented with steps to reproduce
2. Security team reviews security-related defects
3. Severity and priority assigned
4. Developer assigned for remediation
5. Fix implemented and documented
6. QA verification with original test case
7. Security team validation for security issues
8. Closure with documentation of resolution

**Security Defect Handling:**
- Security vulnerabilities tracked in private issue tracker
- Responsible disclosure process for third-party issues
- Security patches prioritized over feature development
- Post-fix verification required by security team
- Root cause analysis for all High and Critical security issues

#### 9. Reporting Approach

**Testing Metrics:**

| Metric | Description | Frequency | Target |
|--------|-------------|-----------|--------|
| Test Coverage | % of requirements covered by tests | Weekly | >95% |
| Security Coverage | % of security controls tested | Weekly | 100% |
| Defect Density | Defects per feature/component | Per release | Decreasing trend |
| Critical/High Bugs | Count of open high-severity issues | Daily | 0 for release |
| Security Vulnerabilities | Count by severity | Daily | 0 Critical/High for release |
| Automation Coverage | % of tests automated | Weekly | >80% |

**Reporting Schedule:**
- Daily: Test execution status and new defects
- Weekly: Comprehensive test status and metrics
- Release: Full test summary with security attestation
- Security: Separate confidential reporting for security issues

**Report Components:**
- Test execution progress
- Defect summary and trends
- Risk assessment
- Security testing status
- Test coverage analysis
- Quality gates status
- Outstanding issues and mitigations

#### 10. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|------------|------------|
| Insufficient time for thorough security testing | High | Medium | Integrate security testing throughout SDLC, automate security tests |
| Test environment instability | Medium | High | Daily environment verification, on-call support for environment issues |
| Incomplete test data | Medium | Medium | Data generation scripts, verification of test data coverage |
| Limited access to security expertise | High | Medium | Training for QA team on security basics, scheduled security team availability |
| Third-party integration limitations | Medium | Medium | Mock services for testing, dedicated test accounts with partners |
| Zero-day vulnerability discovered | High | Low | Incident response plan, rapid patching protocol, WAF rules |

## Security Testing for Test Plans

### Validation Approaches

1. **Peer Review**:
   - Have security experts review the test plan
   - Validate coverage against security requirements
   - Check for security testing gaps

2. **Compliance Mapping**:
   - Map test cases to compliance requirements
   - Verify all regulatory needs are addressed
   - Document compliance coverage

3. **Threat Model Alignment**:
   - Review test plan against system threat model
   - Ensure all identified threats have test coverage
   - Prioritize tests based on risk assessment

### Common Test Plan Vulnerabilities

- **Insufficient Security Coverage**: Failing to test all security controls
- **Over-Reliance on Tools**: Automated testing without manual verification
- **Unrealistic Data**: Test data that doesn't reflect real-world scenarios
- **Inadequate Access Testing**: Not testing all user roles and permissions
- **Missing Edge Cases**: Not testing security boundary conditions

## References

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115 Technical Guide to Information Security Testing and Assessment
- OWASP Application Security Verification Standard (ASVS): https://owasp.org/www-project-application-security-verification-standard/
- OWASP Testing Checklist: https://github.com/OWASP/wstg/tree/master/checklist
