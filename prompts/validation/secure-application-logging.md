# Secure Application Logging Prompt

## Overview

This prompt helps you implement comprehensive, secure logging practices for applications of all types. Proper logging is essential for security monitoring, incident response, compliance, and troubleshooting. Use this prompt to guide Copilot in creating secure logging configurations and implementations.

## How to Use This Prompt

1. Provide the programming language and framework context
2. Specify what type of logging you need (security events, application errors, audit trails, etc.)
3. Include any compliance requirements (e.g., PCI DSS, HIPAA, SOC2, etc.)
4. Ask for specific security considerations if needed

## Example Prompts

```
Create a secure logging setup for a Node.js Express application handling payment processing. The logging should be compliant with PCI DSS requirements, include audit trails for administrative actions, and avoid logging sensitive data.
```

```
Implement secure logging for a Python Django healthcare application that handles PHI. The logs should be structured for SIEM integration, properly handle sensitive data in accordance with HIPAA, and include proper retention controls.
```

## Secure Logging Requirements

### 1. Logging Coverage
- Security events (authentication, authorization, access control)
- System events (startup, shutdown, configuration changes)
- Application errors and exceptions
- User and administrative actions
- Data access and modification events
- API requests and responses (with proper data filtering)

### 2. Event Data Requirements
- Timestamp with consistent timezone (preferably UTC)
- Event type/severity/category
- Source information (service, component, file)
- User or system identity
- Action performed
- Resource accessed or modified
- Result of the action (success/failure)
- Correlation IDs for request tracing

### 3. Data Protection
- No sensitive data in logs (passwords, tokens, PII, PHI)
- Proper data masking and filtering
- Secure handling of error messages
- Secure storage of logs
- Access controls for log data

### 4. Implementation Considerations
- Performance optimization
- Log rotation and retention policies
- Prevention of log injection attacks
- Fail-open logging (errors in logging don't affect application)
- Proper exception handling

## Implementation Examples

### Node.js Express Secure Logging

```javascript
// Using Winston for structured logging with security best practices
const winston = require('winston');
const expressWinston = require('express-winston');
const { createLogger, format, transports } = winston;
const { combine, timestamp, json, errors } = format;

// Sensitive data patterns to mask
const sensitiveDataPatterns = [
  { regex: /(password["']?\s*[:=]\s*["']?)(.+?)(["'])/gi, replacement: '$1[REDACTED]$3' },
  { regex: /(\b(?:visa|mastercard|amex|discover)\b["']?\s*[:=]\s*["']?)([0-9\s-]{10,})(["'])/gi, replacement: '$1[REDACTED]$3' },
  { regex: /(\b(?:ssn|social|tax)["']?\s*[:=]\s*["']?)([0-9-]{9,11})(["'])/gi, replacement: '$1[REDACTED]$3' },
  { regex: /(Authorization["']?\s*:\s*["']?Bearer\s+)([A-Za-z0-9_\-\.=]+)(["']?)/gi, replacement: '$1[REDACTED]$3' },
];

// Custom format to mask sensitive data
const maskSensitiveData = format((info) => {
  if (info.message) {
    let maskedMessage = info.message;
    sensitiveDataPatterns.forEach(pattern => {
      maskedMessage = maskedMessage.replace(pattern.regex, pattern.replacement);
    });
    info.message = maskedMessage;
  }
  
  // Also check objects for sensitive data
  if (info.meta) {
    info.meta = maskSensitiveDataInObject(info.meta);
  }
  
  return info;
});

// Helper to mask data in objects recursively
function maskSensitiveDataInObject(obj) {
  const sensitiveFields = ['password', 'secret', 'token', 'authorization', 'creditCard', 'ssn'];
  
  const masked = { ...obj };
  
  Object.keys(masked).forEach(key => {
    if (sensitiveFields.includes(key.toLowerCase())) {
      masked[key] = '[REDACTED]';
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveDataInObject(masked[key]);
    } else if (typeof masked[key] === 'string') {
      // Check string values against patterns
      sensitiveDataPatterns.forEach(pattern => {
        masked[key] = masked[key].replace(pattern.regex, pattern.replacement);
      });
    }
  });
  
  return masked;
}

// Create secure application logger
const appLogger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    errors({ stack: true }),
    maskSensitiveData(),
    json()
  ),
  defaultMeta: { 
    service: 'payment-service', 
    environment: process.env.NODE_ENV || 'development',
  },
  transports: [
    // Console transport for development
    new transports.Console({
      level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
    }),
    // File transport with rotation for production
    new transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    }),
    new transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 10485760, // 10MB
      maxFiles: 10,
    }),
  ],
  // Avoid exiting on errors in the logging itself
  exitOnError: false,
});

// Add secure HTTP request logging middleware
const requestLogger = expressWinston.logger({
  winstonInstance: appLogger,
  level: 'info',
  // Don't log sensitive body fields
  requestFilter: (req, propName) => {
    if (propName === 'body') {
      const filteredBody = { ...req.body };
      const sensitiveFields = ['password', 'secret', 'token', 'creditCard', 'ssn'];
      
      sensitiveFields.forEach(field => {
        if (filteredBody[field]) {
          filteredBody[field] = '[REDACTED]';
        }
      });
      
      return filteredBody;
    }
    return req[propName];
  },
  // Don't include request/response bodies by default
  requestWhitelist: ['url', 'method', 'httpVersion', 'originalUrl', 'query'],
  responseWhitelist: ['statusCode', 'responseTime'],
  // Include headers but filter out cookies and auth
  ignoredRoutes: ['/health', '/metrics'],
  headerBlacklist: ['cookie', 'authorization'],
});

// Export secure loggers
module.exports = {
  appLogger,
  requestLogger,
  // Security event logging helper
  securityLogger: {
    logAuthenticationEvent: (userId, success, ipAddress, userAgent, details) => {
      appLogger.log({
        level: success ? 'info' : 'warn',
        message: `Authentication ${success ? 'success' : 'failure'} for user ${userId}`,
        eventType: 'AUTHENTICATION',
        userId,
        ipAddress,
        userAgent,
        details,
        timestamp: new Date().toISOString(),
      });
    },
    logAccessControlEvent: (userId, resource, action, success, details) => {
      appLogger.log({
        level: success ? 'info' : 'warn',
        message: `Access control ${success ? 'granted' : 'denied'} for user ${userId} to ${action} ${resource}`,
        eventType: 'ACCESS_CONTROL',
        userId,
        resource,
        action,
        success,
        details,
        timestamp: new Date().toISOString(),
      });
    },
    logDataAccessEvent: (userId, dataType, recordId, action) => {
      appLogger.log({
        level: 'info',
        message: `Data ${action} by user ${userId} on ${dataType} record ${recordId}`,
        eventType: 'DATA_ACCESS',
        userId,
        dataType,
        recordId,
        action,
        timestamp: new Date().toISOString(),
      });
    },
    logAdminEvent: (userId, action, target, details) => {
      appLogger.log({
        level: 'info',
        message: `Administrative action: ${action} performed by ${userId} on ${target}`,
        eventType: 'ADMIN',
        userId,
        action,
        target,
        details,
        timestamp: new Date().toISOString(),
      });
    },
  },
};

// Example usage in Express app
const express = require('express');
const { appLogger, requestLogger, securityLogger } = require('./logging');
const app = express();

// Apply request logging middleware
app.use(requestLogger);

// Example security event logging
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Authentication logic...
    const success = true; // replace with actual auth result
    const userId = 'user123'; // replace with actual user ID
    
    securityLogger.logAuthenticationEvent(
      userId,
      success,
      req.ip,
      req.get('user-agent'),
      { method: 'password' }
    );
    
    // Rest of login logic...
    res.status(200).json({ success: true, token: 'jwt-token-here' });
  } catch (error) {
    // Log security event for failed login
    securityLogger.logAuthenticationEvent(
      username, 
      false,
      req.ip,
      req.get('user-agent'),
      { reason: error.message }
    );
    
    // Log application error
    appLogger.error(`Login error: ${error.message}`, { 
      error: error.name,
      stack: error.stack,
      user: username
    });
    
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
});

// Global error handler with secure error logging
app.use((err, req, res, next) => {
  appLogger.error(`Unhandled application error: ${err.message}`, {
    error: err.name,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
    path: req.path,
    method: req.method
  });
  
  // Don't expose error details in production
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : err.message
  });
});
```

### Python Django Secure Logging

```python
# settings.py

# Structured logging configuration with security best practices
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s %(pathname)s %(lineno)d %(funcName)s %(contextual_data)s',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'sensitive_data_filter': {
            '()': 'app.logging_filters.SensitiveDataFilter',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
        'secure_file': {
            'level': 'INFO',
            'filters': ['sensitive_data_filter'],
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs/app.log'),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
            'encoding': 'utf8',
        },
        'security_file': {
            'level': 'INFO',
            'filters': ['sensitive_data_filter'],
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs/security.log'),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 20,
            'formatter': 'json',
            'encoding': 'utf8',
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false', 'sensitive_data_filter'],
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'secure_file'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.server': {
            'handlers': ['console', 'secure_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['mail_admins', 'secure_file'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['secure_file'],
            'level': 'ERROR',
            'propagate': False,
        },
        'app.security': {
            'handlers': ['security_file', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },
        'app': {
            'handlers': ['console', 'secure_file'],
            'level': 'INFO',
            'propagate': False,
        },
    }
}
```

```python
# app/logging_filters.py
import logging
import re

class SensitiveDataFilter(logging.Filter):
    """Filter to mask sensitive data in logs"""
    
    def __init__(self):
        super().__init__()
        # Regular expressions for sensitive data
        self.patterns = [
            # Passwords
            (re.compile(r'(password["\']\s*[:=]\s*["\'])(.+?)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
            # Credit card numbers
            (re.compile(r'(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})'), r'\1-XXXX-XXXX-\4'),
            # SSN
            (re.compile(r'(\b\d{3})[- ]?(\d{2})[- ]?(\d{4}\b)'), r'\1-XX-\3'),
            # Email addresses in specific contexts
            (re.compile(r'(email["\']\s*[:=]\s*["\'])(.+?)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
            # Auth tokens and keys
            (re.compile(r'(auth|token|api[-_]?key|secret)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE), r'\1=["\'"][REDACTED]["\']'),
            # JWT or bearer tokens
            (re.compile(r'(bearer\s+)([a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)', re.IGNORECASE), r'\1[REDACTED]'),
        ]
        
        # Fields to completely redact
        self.sensitive_fields = [
            'password', 'secret', 'token', 'key', 'auth', 'credentials', 
            'credit_card', 'creditcard', 'ssn', 'social_security',
            'birth_date', 'birthdate', 'dob'
        ]

    def filter(self, record):
        # Don't modify the original record
        if not hasattr(record, 'contextual_data'):
            record.contextual_data = {}
            
        # Apply regex replacements to message strings
        if isinstance(record.msg, str):
            for pattern, repl in self.patterns:
                record.msg = pattern.sub(repl, record.msg)
                
        # Mask sensitive values in extra args if present
        if hasattr(record, 'args') and record.args:
            args_list = list(record.args)
            for i, arg in enumerate(args_list):
                if isinstance(arg, str):
                    for pattern, repl in self.patterns:
                        args_list[i] = pattern.sub(repl, arg)
                elif isinstance(arg, dict):
                    args_list[i] = self._filter_dict(arg)
            record.args = tuple(args_list)
            
        # Process the contextual data
        if hasattr(record, 'contextual_data') and record.contextual_data:
            record.contextual_data = self._filter_dict(record.contextual_data)
        
        return True
    
    def _filter_dict(self, data):
        """Recursively filter dictionary values"""
        if not isinstance(data, dict):
            return data
            
        filtered = {}
        
        for key, value in data.items():
            # Check if the key is sensitive
            if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = self._filter_dict(value)
            elif isinstance(value, (list, tuple)):
                filtered[key] = [
                    self._filter_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            elif isinstance(value, str):
                # Apply patterns to string values
                filtered_value = value
                for pattern, repl in self.patterns:
                    filtered_value = pattern.sub(repl, filtered_value)
                filtered[key] = filtered_value
            else:
                filtered[key] = value
                
        return filtered
```

```python
# app/security_logger.py
import logging
import threading
import uuid
from datetime import datetime
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()
security_logger = logging.getLogger('app.security')
app_logger = logging.getLogger('app')

# Thread local storage for request context
_thread_locals = threading.local()

def get_request_context():
    """Get the current request context from thread local storage"""
    context = getattr(_thread_locals, 'context', {})
    if not context:
        context = {'correlation_id': str(uuid.uuid4())}
        _thread_locals.context = context
    return context

def set_request_context(request=None, user=None, correlation_id=None):
    """Set context information for the current request thread"""
    context = get_request_context()
    
    if correlation_id:
        context['correlation_id'] = correlation_id
    elif request and request.headers.get('X-Correlation-ID'):
        context['correlation_id'] = request.headers['X-Correlation-ID']
        
    if user and user.is_authenticated:
        context['user_id'] = user.id
        context['username'] = user.username
        
    if request:
        context['ip_address'] = request.META.get('REMOTE_ADDR', '')
        context['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
        
    _thread_locals.context = context
    return context

class SecurityEvents:
    """Security event logging helper class"""
    
    @staticmethod
    def _get_base_event_data():
        """Get common event data to include in all security logs"""
        context = get_request_context()
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': context.get('correlation_id', str(uuid.uuid4())),
            'user_id': context.get('user_id', 'anonymous'),
            'username': context.get('username', 'anonymous'),
            'ip_address': context.get('ip_address', 'unknown'),
            'user_agent': context.get('user_agent', 'unknown'),
            'environment': settings.ENVIRONMENT,
            'application': 'healthcare_app',
        }
        
    @classmethod
    def authentication(cls, success, user=None, username=None, method='password', details=None):
        """Log authentication events"""
        event_data = cls._get_base_event_data()
        
        if user and hasattr(user, 'username'):
            user_id = getattr(user, 'id', 'unknown')
            username = user.username
        else:
            user_id = 'unknown'
            username = username or 'unknown'
            
        event_data.update({
            'event_type': 'AUTHENTICATION',
            'event_severity': 'WARNING' if not success else 'INFO',
            'user_id': user_id,
            'username': username, 
            'auth_method': method,
            'success': success,
            'details': details or {},
        })
        
        security_logger.warning(f"Authentication {'success' if success else 'failure'} for user {username}",
                            extra={'contextual_data': event_data})
                            
    @classmethod
    def authorization(cls, user, resource, action, success, details=None):
        """Log authorization/access control events"""
        event_data = cls._get_base_event_data()
        
        if user and hasattr(user, 'username'):
            user_id = getattr(user, 'id', 'unknown')
            username = user.username
        else:
            user_id = 'unknown'
            username = 'unknown'
            
        event_data.update({
            'event_type': 'AUTHORIZATION',
            'event_severity': 'WARNING' if not success else 'INFO',
            'user_id': user_id,
            'username': username,
            'resource': resource,
            'action': action,
            'success': success,
            'details': details or {},
        })
        
        security_logger.warning(
            f"Access {'granted' if success else 'denied'} for user {username} to {action} {resource}",
            extra={'contextual_data': event_data}
        )
    
    @classmethod
    def data_access(cls, user, data_type, record_id, action, details=None):
        """Log PHI/sensitive data access events"""
        event_data = cls._get_base_event_data()
        
        if user and hasattr(user, 'username'):
            user_id = getattr(user, 'id', 'unknown')
            username = user.username
        else:
            user_id = 'unknown'
            username = 'unknown'
            
        event_data.update({
            'event_type': 'DATA_ACCESS',
            'event_severity': 'INFO',
            'user_id': user_id,
            'username': username,
            'data_type': data_type,
            'record_id': record_id,
            'action': action,
            'details': details or {},
        })
        
        security_logger.info(
            f"Data {action} by user {username} on {data_type} record {record_id}",
            extra={'contextual_data': event_data}
        )
    
    @classmethod
    def system_event(cls, event_name, component=None, status=None, details=None):
        """Log system events like startup, shutdown, config changes"""
        event_data = cls._get_base_event_data()
        
        event_data.update({
            'event_type': 'SYSTEM',
            'event_severity': 'INFO',
            'event_name': event_name,
            'component': component or 'system',
            'status': status or 'info',
            'details': details or {},
        })
        
        security_logger.info(
            f"System event: {event_name} in {component or 'system'} with status {status or 'info'}",
            extra={'contextual_data': event_data}
        )
```

```python
# app/middleware.py
from .security_logger import set_request_context, SecurityEvents
import time
import uuid

class SecurityLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Generate correlation ID if not provided
        correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
        
        # Set request context for logging
        set_request_context(
            request=request,
            user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
            correlation_id=correlation_id
        )
        
        # Record request start time for performance logging
        request.start_time = time.time()
        
        # Process request and get response
        response = self.get_response(request)
        
        # Add correlation ID to response headers
        response['X-Correlation-ID'] = correlation_id
        
        # Log successful responses for sensitive operations
        sensitive_paths = [
            '/admin/', 
            '/api/patients/', 
            '/api/medical-records/',
            '/api/billing/'
        ]
        
        if any(request.path.startswith(path) for path in sensitive_paths):
            # For sensitive operations, log access (but only log data access details for reads, not the data itself)
            SecurityEvents.data_access(
                user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                data_type=request.path.split('/')[2] if len(request.path.split('/')) > 2 else 'unknown',
                record_id=request.path.split('/')[-1] if request.path.split('/')[-1].isdigit() else 'multiple',
                action=request.method,
                details={
                    'path': request.path,
                    'method': request.method,
                    'status_code': response.status_code,
                    'response_time_ms': int((time.time() - request.start_time) * 1000),
                }
            )
        
        return response
        
    def process_exception(self, request, exception):
        # Log unhandled exceptions
        app_logger = logging.getLogger('app')
        app_logger.error(
            f"Unhandled exception: {str(exception)}",
            exc_info=True,
            extra={
                'contextual_data': {
                    'path': request.path,
                    'method': request.method,
                    'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
                    'exception_type': type(exception).__name__,
                }
            }
        )
        return None
```

### Java Spring Boot Secure Logging

```java
// Application.properties
# Logging configuration
logging.level.root=INFO
logging.level.org.springframework.web=INFO
logging.level.com.example.secureapp=DEBUG
logging.level.com.example.secureapp.security=INFO

# Use JSON format for logs
logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} %highlight(%-5level) [%thread] %cyan(%logger{15}) - %msg %X{user} %X{sessionId} %X{correlationId} %n
logging.pattern.file=%d{yyyy-MM-dd HH:mm:ss} %-5level [%thread] %logger{15} - %msg %X{user} %X{sessionId} %X{correlationId} %n

# Log file configuration
logging.file.name=logs/application.log
logging.file.max-size=10MB
logging.file.max-history=10
logging.file.total-size-cap=100MB

# Security audit log
app.security.audit-file=logs/security-audit.log
```

```java
// SecurityLogger.java
package com.example.secureapp.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Component
public class SecurityLogger {

    private static final Logger securityLogger = LoggerFactory.getLogger("com.example.secureapp.security");
    private static final Logger appLogger = LoggerFactory.getLogger("com.example.secureapp");
    
    @Value("${app.environment:production}")
    private String environment;

    /**
     * Log authentication events
     * @param userId User identifier
     * @param username Username
     * @param success Whether authentication was successful
     * @param ipAddress Client IP address
     * @param userAgent Client user agent
     * @param method Authentication method (password, token, etc)
     * @param details Additional contextual details
     */
    public void logAuthenticationEvent(String userId, String username, boolean success,
                                      String ipAddress, String userAgent, String method,
                                      Map<String, Object> details) {
        try {
            SecurityEventBuilder builder = SecurityEventBuilder.create("AUTHENTICATION")
                    .userId(userId)
                    .username(username)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .success(success)
                    .severity(success ? "INFO" : "WARNING")
                    .detail("method", method);
                    
            if (details != null) {
                details.forEach(builder::detail);
            }
            
            String eventMessage = String.format("Authentication %s for user %s", 
                    success ? "success" : "failure", username);
                    
            securityLogger.info(eventMessage, builder.build());
        } catch (Exception e) {
            // Fail safe - log the error but don't break application flow
            appLogger.error("Failed to log security event: " + e.getMessage(), e);
        }
    }
    
    /**
     * Log authorization/access control events
     * @param userId User identifier
     * @param username Username
     * @param resource Protected resource being accessed
     * @param action Action being performed
     * @param success Whether access was granted
     * @param details Additional contextual details
     */
    public void logAccessControlEvent(String userId, String username, String resource,
                                    String action, boolean success, Map<String, Object> details) {
        try {
            SecurityEventBuilder builder = SecurityEventBuilder.create("ACCESS_CONTROL")
                    .userId(userId)
                    .username(username)
                    .success(success)
                    .severity(success ? "INFO" : "WARNING")
                    .detail("resource", resource)
                    .detail("action", action);
                    
            if (details != null) {
                details.forEach(builder::detail);
            }
            
            String eventMessage = String.format("Access %s for user %s to %s %s",
                    success ? "granted" : "denied", username, action, resource);
                    
            securityLogger.info(eventMessage, builder.build());
        } catch (Exception e) {
            appLogger.error("Failed to log security event: " + e.getMessage(), e);
        }
    }
    
    /**
     * Log data access events, particularly for sensitive data
     * @param userId User identifier
     * @param username Username
     * @param dataType Type of data being accessed
     * @param recordId Record identifier
     * @param action Action performed (READ, CREATE, UPDATE, DELETE)
     * @param details Additional contextual details
     */
    public void logDataAccessEvent(String userId, String username, String dataType,
                                  String recordId, String action, Map<String, Object> details) {
        try {
            SecurityEventBuilder builder = SecurityEventBuilder.create("DATA_ACCESS")
                    .userId(userId)
                    .username(username)
                    .severity("INFO")
                    .detail("dataType", dataType)
                    .detail("recordId", recordId)
                    .detail("action", action);
                    
            if (details != null) {
                details.forEach(builder::detail);
            }
            
            String eventMessage = String.format("Data %s by user %s on %s record %s",
                    action, username, dataType, recordId);
                    
            securityLogger.info(eventMessage, builder.build());
        } catch (Exception e) {
            appLogger.error("Failed to log security event: " + e.getMessage(), e);
        }
    }
    
    /**
     * Log system events like startup, shutdown, and configuration changes
     * @param eventName Name of the event
     * @param component System component
     * @param status Status or result
     * @param details Additional contextual details
     */
    public void logSystemEvent(String eventName, String component, String status, 
                              Map<String, Object> details) {
        try {
            SecurityEventBuilder builder = SecurityEventBuilder.create("SYSTEM")
                    .severity("INFO")
                    .detail("eventName", eventName)
                    .detail("component", component)
                    .detail("status", status);
                    
            if (details != null) {
                details.forEach(builder::detail);
            }
            
            String eventMessage = String.format("System event: %s in %s with status %s",
                    eventName, component, status);
                    
            securityLogger.info(eventMessage, builder.build());
        } catch (Exception e) {
            appLogger.error("Failed to log security event: " + e.getMessage(), e);
        }
    }
    
    /**
     * Builder for security events with consistent formatting
     */
    private static class SecurityEventBuilder {
        private final Map<String, Object> event;
        
        private SecurityEventBuilder(String eventType) {
            event = new HashMap<>();
            event.put("eventType", eventType);
            event.put("timestamp", Instant.now().toString());
            event.put("correlationId", MDC.get("correlationId") != null ? 
                    MDC.get("correlationId") : UUID.randomUUID().toString());
            event.put("environment", environment);
        }
        
        public static SecurityEventBuilder create(String eventType) {
            return new SecurityEventBuilder(eventType);
        }
        
        public SecurityEventBuilder userId(String userId) {
            event.put("userId", userId);
            return this;
        }
        
        public SecurityEventBuilder username(String username) {
            event.put("username", username);
            return this;
        }
        
        public SecurityEventBuilder ipAddress(String ipAddress) {
            event.put("ipAddress", ipAddress);
            return this;
        }
        
        public SecurityEventBuilder userAgent(String userAgent) {
            event.put("userAgent", userAgent);
            return this;
        }
        
        public SecurityEventBuilder success(boolean success) {
            event.put("success", success);
            return this;
        }
        
        public SecurityEventBuilder severity(String severity) {
            event.put("severity", severity);
            return this;
        }
        
        public SecurityEventBuilder detail(String key, Object value) {
            event.put(key, value);
            return this;
        }
        
        public Map<String, Object> build() {
            return event;
        }
    }
}
```

```java
// SensitiveDataFilter.java
package com.example.secureapp.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;
import org.slf4j.Marker;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Logback filter that prevents sensitive data from being logged
 */
public class SensitiveDataFilter extends Filter<ILoggingEvent> {

    // Patterns to detect sensitive data in log messages
    private static final List<Pattern> SENSITIVE_PATTERNS = Arrays.asList(
        // Credit card numbers
        Pattern.compile("\\b(?:\\d{4}[- ]?){3}\\d{4}\\b"),
        // Social security numbers
        Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"),
        // Passwords in various formats
        Pattern.compile("(?i)password[\\s\"':=]+[^\\s,;\\)]+"),
        // Bearer tokens
        Pattern.compile("(?i)bearer\\s+[A-Za-z0-9_\\-\\.=]+"),
        // API keys and secrets
        Pattern.compile("(?i)api[_-]?key[\\s\"':=]+[^\\s,;\\)]+"),
        Pattern.compile("(?i)(secret|token)[\\s\"':=]+[^\\s,;\\)]+")
    );
    
    // List of keywords that indicate potentially sensitive data
    private static final List<String> SENSITIVE_KEYWORDS = Arrays.asList(
        "password", "secret", "token", "key", "credential", "auth", 
        "ssn", "creditcard", "credit", "cvv", "social"
    );

    @Override
    public FilterReply decide(ILoggingEvent event) {
        if (event == null) {
            return FilterReply.NEUTRAL;
        }
        
        String message = event.getMessage();
        if (message == null) {
            return FilterReply.NEUTRAL;
        }
        
        // Check message for sensitive data patterns
        for (Pattern pattern : SENSITIVE_PATTERNS) {
            if (pattern.matcher(message).find()) {
                // If sensitive pattern found, redact the message
                // Instead of blocking entirely, we could replace with redacted version
                return FilterReply.DENY;
            }
        }
        
        // Check message arguments for sensitive data keywords
        if (event.getArgumentArray() != null) {
            for (Object arg : event.getArgumentArray()) {
                if (arg != null) {
                    String argStr = arg.toString().toLowerCase();
                    for (String keyword : SENSITIVE_KEYWORDS) {
                        if (argStr.contains(keyword)) {
                            return FilterReply.DENY;
                        }
                    }
                }
            }
        }
        
        // No sensitive data detected
        return FilterReply.NEUTRAL;
    }
}
```

```java
// RequestLoggingFilter.java
package com.example.secureapp.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);
    
    private static final List<String> SENSITIVE_HEADERS = Arrays.asList(
        "authorization", "cookie", "x-api-key"
    );
    
    private static final List<String> SENSITIVE_PARAMETERS = Arrays.asList(
        "password", "token", "key", "secret", "credential", "creditcard"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
            throws ServletException, IOException {
            
        long startTime = System.currentTimeMillis();
        
        // Generate correlation ID if not present
        String correlationId = request.getHeader("X-Correlation-ID");
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }
        
        // Add correlation ID to MDC for logging context
        MDC.put("correlationId", correlationId);
        
        // Add user info to MDC if authenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
            SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            MDC.put("user", SecurityContextHolder.getContext().getAuthentication().getName());
            MDC.put("sessionId", request.getSession().getId());
        }
        
        // Create wrappers to cache request/response content for logging
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        
        try {
            // Log incoming request (but filter sensitive data)
            logRequest(requestWrapper);
            
            // Process the request
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            // Log response
            logResponse(responseWrapper, System.currentTimeMillis() - startTime);
            
            // Copy content to the original response
            responseWrapper.copyBodyToResponse();
            
            // Add correlation ID to response header
            response.setHeader("X-Correlation-ID", correlationId);
            
            // Clear MDC
            MDC.clear();
        }
    }

    private void logRequest(ContentCachingRequestWrapper request) {
        StringBuilder message = new StringBuilder()
                .append("HTTP Request: ")
                .append(request.getMethod())
                .append(" ")
                .append(request.getRequestURI());
                
        // Append query string if present
        String queryString = request.getQueryString();
        if (queryString != null) {
            message.append("?").append(sanitizeValues(queryString));
        }
        
        // Log request headers (excluding sensitive ones)
        Map<String, String> headers = new HashMap<>();
        Collections.list(request.getHeaderNames()).forEach(headerName -> {
            if (!SENSITIVE_HEADERS.contains(headerName.toLowerCase())) {
                headers.put(headerName, request.getHeader(headerName));
            } else {
                headers.put(headerName, "[REDACTED]");
            }
        });
        
        // Log request parameters (excluding sensitive ones)
        Map<String, String> parameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (SENSITIVE_PARAMETERS.stream().anyMatch(param -> key.toLowerCase().contains(param))) {
                parameters.put(key, "[REDACTED]");
            } else {
                parameters.put(key, Arrays.toString(values));
            }
        });
        
        // Don't log request body - it may contain sensitive data
        // For specific endpoints that need body logging, use a separate filter
        
        log.info(message.toString(), 
            Map.of(
                "headers", headers,
                "parameters", parameters,
                "clientIP", request.getRemoteAddr()
            ));
    }

    private void logResponse(ContentCachingResponseWrapper response, long executionTime) {
        StringBuilder message = new StringBuilder()
                .append("HTTP Response: ")
                .append(response.getStatus())
                .append(" (").append(TimeUnit.MILLISECONDS.toMillis(executionTime)).append(" ms)");
        
        // Don't log response body - it may contain sensitive data
        
        log.info(message.toString(), 
            Map.of(
                "status", response.getStatus(),
                "executionTime", executionTime
            ));
    }
    
    private String sanitizeValues(String input) {
        // Simple sanitization of potentially sensitive values
        for (String param : SENSITIVE_PARAMETERS) {
            // Look for parameter=value patterns and redact the value
            Pattern pattern = Pattern.compile("(" + param + "=)[^&]+", Pattern.CASE_INSENSITIVE);
            input = pattern.matcher(input).replaceAll("$1[REDACTED]");
        }
        return input;
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip logging for specific paths
        String path = request.getRequestURI();
        return path.contains("/health") || 
               path.contains("/metrics") || 
               path.contains("/actuator") ||
               path.contains("/favicon.ico");
    }
}
```

## Security Considerations for Logging

### 1. Sensitive Data Protection
- Never log passwords, credentials, or authentication tokens
- Apply masking for sensitive data patterns (credit cards, SSNs, etc.)
- Create a sensitive data filtering mechanism
- Ensure error messages don't reveal implementation details
- Be careful with stack traces in production environments

### 2. Log Storage Security
- Implement proper access controls for log files/databases
- Consider encryption for sensitive logs
- Implement log rotation and retention policies
- Separate application logs from security event logs
- Consider secure centralized logging

### 3. Log Integrity
- Use correlation IDs to track requests across systems
- Include timestamps in a consistent format (ISO 8601, UTC)
- Add source information (service, component, instance)
- Implement tamper-evident logging where needed
- Consider log signing for critical security events

### 4. Compliance Requirements
- **PCI DSS**: Retain logs for at least 1 year, with 3 months immediately accessible
- **HIPAA**: Implement hardware, software, and procedural mechanisms to record and examine access to systems with PHI
- **SOC2**: Maintain evidence of security monitoring and timely action on security events
- **GDPR**: Ensure personal data in logs is protected and maintained according to retention policies

### 5. Performance Considerations
- Implement asynchronous logging for high-volume systems
- Use structured logging formats (JSON) for easier parsing
- Consider log levels to control verbosity
- Implement circuit breakers for logging failures
- Batch log messages when appropriate

## Best Practices

1. **Use structured logging formats** (JSON) for machine-readability
2. **Implement proper log levels** (DEBUG, INFO, WARN, ERROR) consistently
3. **Create dedicated security event logs** separate from application logs
4. **Centralize log collection** for monitoring and analysis
5. **Implement log rotation** to prevent disk space issues
6. **Use correlation IDs** to trace requests across services
7. **Add context to log entries** (user ID, request ID, etc.)
8. **Test logging configuration** in development environments
9. **Monitor logging performance** to prevent impact on application
10. **Regularly review and audit logs** for security issues
