# Secure Coding Prompt: General Threat Modeling

## Purpose

This prompt guides you in conducting comprehensive threat modeling for software systems across various environments and technologies. Use this prompt to identify, analyze, and document potential threats to your applications, services, and infrastructure.

## General Threat Modeling Prompt

```
As a security-focused threat modeler, help me conduct a threat model for [SYSTEM/APPLICATION NAME].

System information:
1. Description: [Brief description of the system/application]
2. Architecture: [Client-server, microservices, serverless, etc.]
3. Technologies: [Programming languages, frameworks, databases, cloud services]
4. User types: [Customer, administrator, service account, etc.]
5. Data sensitivity: [Public, internal, confidential, regulated]
6. Deployment environment: [Cloud provider, on-premise, hybrid]

Consider these threat modeling aspects:
1. Asset identification
2. Trust boundaries
3. Data flows
4. Entry points
5. Privilege levels
6. Threat actors and their motivations
7. Attack surface analysis
8. Potential vulnerabilities and threats
9. Risk assessment (impact and likelihood)
10. Security controls and mitigations

Please use the STRIDE framework to categorize threats:
- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

For each identified threat, provide:
1. Description of the threat
2. Associated STRIDE category
3. Affected components/data flows
4. Risk level (High/Medium/Low)
5. Potential mitigations
6. Implementation recommendations
```

## Threat Modeling Process

### 1. Define the Scope

Start by clearly defining what's included in the threat model:
- System/application boundaries
- Key components and interactions
- In-scope vs. out-of-scope elements
- Assumptions and preconditions

### 2. Create a System Model

Develop a visual representation of the system:
- Component diagrams
- Data flow diagrams
- Trust boundary diagrams
- Use cases and user stories

### 3. Identify Assets

Document what needs to be protected:
- Sensitive data (PII, financial, intellectual property)
- Critical functionality
- System availability requirements
- Reputation considerations

### 4. Threat Identification

Use structured methods to identify potential threats:
- STRIDE framework mapping
- Attack trees
- Threat libraries and patterns
- Historical incidents in similar systems

### 5. Risk Assessment

Evaluate each identified threat:
- Likelihood of occurrence
- Potential impact if exploited
- Risk scoring methodology
- Prioritization of threats

### 6. Mitigation Planning

Develop security controls for each significant threat:
- Preventive measures
- Detective measures
- Responsive measures
- Compliance requirements

### 7. Validation

Review and verify the threat model:
- Completeness of analysis
- Accuracy of assumptions
- Effectiveness of proposed mitigations
- Residual risks assessment

## Example Threat Model: E-Commerce Website

### System Overview

**System Name**: MyShop E-Commerce Platform
**Description**: Web-based retail platform that allows customers to browse products, make purchases, and manage their accounts.
**Architecture**: Three-tier architecture (web frontend, API layer, database)
**Technologies**:
- Frontend: React.js
- Backend: Node.js, Express
- Database: PostgreSQL
- Authentication: OAuth 2.0 with JWT
- Payment Processing: Third-party payment gateway
- Hosting: AWS (EC2, RDS, S3)

### Asset Identification

1. **Customer Data**
   - Personal Information (PII)
   - Payment Information
   - Purchase History
   - Account Credentials

2. **Business Data**
   - Product Catalog
   - Inventory Information
   - Pricing Strategy
   - Sales Analytics

3. **System Components**
   - Web Application
   - API Services
   - Database
   - Authentication System
   - Payment Processing Integration

### Trust Boundaries

1. **External to Web Application**
   - Customer browsers to web frontend
   - Mobile apps to API endpoints

2. **Application to Database**
   - API services to database

3. **Application to External Services**
   - API services to payment processor
   - API services to email service provider

4. **Internal Service Boundaries**
   - Authentication service to other services
   - Product service to order service

### Threat Analysis (STRIDE)

#### 1. Spoofing

**Threat**: Attacker impersonates a legitimate user
**Risk Level**: High
**Affected Components**: Authentication system, user sessions
**Mitigation**:
- Implement strong authentication mechanisms (MFA)
- Use secure session management
- Implement proper token validation
- Apply account lockout policies
- Monitor for unusual login patterns

#### 2. Tampering

**Threat**: Unauthorized modification of product data or prices
**Risk Level**: Medium
**Affected Components**: Product database, API endpoints
**Mitigation**:
- Implement proper access controls
- Use input validation
- Implement integrity checks
- Log all data modifications
- Use parameterized queries to prevent SQL injection

#### 3. Repudiation

**Threat**: User denies making a purchase or transaction
**Risk Level**: Medium
**Affected Components**: Order system, payment system
**Mitigation**:
- Implement comprehensive logging
- Use digital signatures for transactions
- Maintain audit trails
- Send confirmation emails/notifications
- Store transaction metadata (IP, device info, timestamps)

#### 4. Information Disclosure

**Threat**: Exposure of customer PII or payment information
**Risk Level**: High
**Affected Components**: Database, API endpoints, logs
**Mitigation**:
- Encrypt sensitive data at rest
- Implement TLS for data in transit
- Apply proper access controls
- Minimize data collection
- Implement data masking in logs
- Regular security testing

#### 5. Denial of Service

**Threat**: Overloading the website to prevent legitimate access
**Risk Level**: Medium
**Affected Components**: Web servers, API endpoints
**Mitigation**:
- Implement rate limiting
- Use CDN services
- Configure auto-scaling
- Deploy DDoS protection
- Implement circuit breakers
- Monitor system health

#### 6. Elevation of Privilege

**Threat**: Customer gains administrative access
**Risk Level**: High
**Affected Components**: Authorization system, admin interfaces
**Mitigation**:
- Implement role-based access control
- Apply principle of least privilege
- Validate authorization for all actions
- Segregate admin functionality
- Regular permission audits

### Implementation Recommendations

#### Authentication & Authorization
```
// JWT verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }
  
  try {
    // Verify token with proper algorithms and options
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['RS256'],
      issuer: 'myshop-auth',
      audience: 'myshop-api'
    });
    
    req.user = decoded;
    next();
  } catch (err) {
    // Log the error but don't expose details
    logger.error('Token verification failed', { error: err.name });
    return res.status(401).json({ message: 'Unauthorized' });
  }
};

// RBAC middleware
const checkRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Usage example
app.get('/admin/users', 
  verifyToken, 
  checkRole(['admin']), 
  adminController.listUsers
);
```

#### Data Protection
```
// Data encryption utility
const crypto = require('crypto');

const encrypt = (text, secretKey) => {
  // Use a random IV for each encryption
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(secretKey, 'hex'),
    iv
  );
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Get the auth tag for integrity verification
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Return IV + encrypted data + auth tag
  return iv.toString('hex') + ':' + encrypted + ':' + authTag;
};

const decrypt = (encryptedText, secretKey) => {
  const parts = encryptedText.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const authTag = Buffer.from(parts[2], 'hex');
  
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(secretKey, 'hex'),
    iv
  );
  
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};
```

## Security Testing Recommendations

1. **Threat Model Validation**
   - Review threat model with cross-functional team
   - Ensure all critical flows are covered
   - Validate assumptions and constraints

2. **Security Testing**
   - Conduct regular penetration testing
   - Perform security code reviews
   - Use automated scanners (SAST, DAST, SCA)
   - Test authentication and authorization controls
   - Verify encryption implementations

3. **Continuous Monitoring**
   - Implement logging and monitoring
   - Set up alerts for suspicious activities
   - Conduct regular security assessments
   - Monitor for new vulnerabilities in dependencies
   - Track security metrics and trends

## References

- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- STRIDE Threat Model: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- MITRE ATT&CK Framework: https://attack.mitre.org/
- Threat Modeling Manifesto: https://www.threatmodelingmanifesto.org/
