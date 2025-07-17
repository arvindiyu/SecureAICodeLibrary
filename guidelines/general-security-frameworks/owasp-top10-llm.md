# OWASP Top 10 for Large Language Model Applications

## Overview

The OWASP Top 10 for Large Language Model (LLM) Applications provides a standardized awareness document for developers and security teams working with LLMs. This document addresses the unique security risks of applications leveraging LLM technologies.

## Top 10 LLM Application Security Risks

1. **LLM01: Prompt Injection**
   - Vulnerability: Malicious user inputs that manipulate the LLM to ignore previous instructions or perform unintended actions
   - Prevention: Input validation, prompt hardening, explicit context boundaries
   - Detection: Input monitoring, response analysis, red team testing

2. **LLM02: Insecure Output Handling**
   - Vulnerability: Blindly trusting LLM outputs which may contain harmful content, code, or instructions
   - Prevention: Output filtering, content policies, sandboxed execution
   - Detection: Content scanning, output validation, security testing

3. **LLM03: Training Data Poisoning**
   - Vulnerability: Manipulation of training data to introduce vulnerabilities, biases, or backdoors
   - Prevention: Training data validation, anomaly detection, data provenance tracking
   - Detection: Model behavior testing, bias detection, anomaly monitoring

4. **LLM04: Model Denial of Service**
   - Vulnerability: Deliberate overloading of the model with complex queries causing resource exhaustion or degraded service
   - Prevention: Resource quotas, rate limiting, compute budgets
   - Detection: Performance monitoring, resource utilization tracking, usage analysis

5. **LLM05: Supply Chain Vulnerabilities**
   - Vulnerability: Security issues in pre-trained models, datasets, or third-party components
   - Prevention: Vendor security assessment, model provenance verification, supply chain monitoring
   - Detection: Dependency scanning, model validation, vendor security reviews

6. **LLM06: Sensitive Information Disclosure**
   - Vulnerability: Models inadvertently revealing sensitive information embedded in their training data
   - Prevention: Training data filtering, information access controls, response sanitization
   - Detection: PII scanning, sensitive information monitoring, privacy testing

7. **LLM07: Insecure Plugin Design**
   - Vulnerability: Inadequate security controls in LLM plugins leading to unauthorized actions
   - Prevention: Plugin security review, least privilege design, sandboxing
   - Detection: Plugin security testing, permission auditing, integration testing

8. **LLM08: Excessive Agency**
   - Vulnerability: Giving LLMs too much autonomy or authority to take actions without proper oversight
   - Prevention: Explicit authorization for actions, human-in-the-loop verification, constrained action space
   - Detection: Agency limit testing, action auditing, simulation testing

9. **LLM09: Overreliance**
   - Vulnerability: Excessive trust in LLM outputs for critical decisions without verification
   - Prevention: Output verification procedures, confidence scoring, multiple validation methods
   - Detection: Decision auditing, verification testing, human oversight assessment

10. **LLM10: Model Theft**
    - Vulnerability: Unauthorized extraction of model architecture, weights, or training data
    - Prevention: Access controls, API rate limiting, input/output monitoring
    - Detection: Unusual query patterns, extraction attempt detection, usage monitoring

## Implementation Guidelines

1. **Input Validation**: Validate and sanitize all inputs before sending to LLMs
2. **Output Verification**: Always verify LLM outputs before actioning them
3. **Least Privilege**: Limit what actions LLMs can perform on behalf of users
4. **Monitoring**: Implement comprehensive monitoring for unusual input patterns or outputs
5. **Rate Limiting**: Apply rate limits to prevent abuse and extraction attacks
6. **Human Oversight**: Maintain human oversight for critical decisions
7. **Privacy Controls**: Implement strict controls for handling personal or sensitive information

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LLM Security Best Practices](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
