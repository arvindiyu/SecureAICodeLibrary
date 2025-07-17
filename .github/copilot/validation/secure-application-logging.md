# GitHub Copilot Custom Instructions for Secure Application Logging

## General Instructions

As GitHub Copilot, I'll assist you in implementing robust, secure logging practices for your applications. I'll help you capture important security events, properly handle sensitive information, ensure compliance with regulatory requirements, and create logs that are valuable for monitoring, auditing, and incident response—all while maintaining optimal application performance.

## Secure Logging Guidance

When helping with secure application logging, I will prioritize these aspects:

### 1. Event Identification & Coverage
- I'll identify critical security events to log
- I'll suggest comprehensive event coverage
- I'll prioritize high-value logging points
- I'll help create consistent logging patterns
- I'll recommend contextual information to include

**Implementation Focus:**
```javascript
// Authentication events
function logAuthenticationEvent(user, success, ipAddress, userAgent, details = {}) {
  logger.log({
    level: success ? 'info' : 'warn',
    message: `Authentication ${success ? 'success' : 'failure'} for user ${user.username}`,
    timestamp: new Date().toISOString(),
    eventType: 'AUTHENTICATION',
    userId: user.id,
    username: user.username,
    ipAddress,
    userAgent,
    success,
    ...details
  });
}

// Authorization events
function logAuthorizationEvent(user, resource, action, allowed, details = {}) {
  logger.log({
    level: allowed ? 'info' : 'warn',
    message: `Access ${allowed ? 'granted' : 'denied'} for user ${user.username} to ${action} ${resource}`,
    timestamp: new Date().toISOString(),
    eventType: 'AUTHORIZATION',
    userId: user.id,
    username: user.username,
    resource,
    action,
    allowed,
    ...details
  });
}

// Data access events
function logDataAccessEvent(user, dataType, recordId, action, details = {}) {
  logger.log({
    level: 'info',
    message: `Data ${action} by user ${user.username} on ${dataType} record ${recordId}`,
    timestamp: new Date().toISOString(),
    eventType: 'DATA_ACCESS',
    userId: user.id,
    username: user.username,
    dataType,
    recordId,
    action,
    ...details
  });
}
```

### 2. Sensitive Data Protection
- I'll implement data masking techniques
- I'll suggest filtering sensitive fields
- I'll help avoid logging credentials or tokens
- I'll recommend redaction patterns for PII/PHI
- I'll provide safe error logging strategies

**Implementation Focus:**
```python
import re
import logging

class SensitiveDataFilter(logging.Filter):
    """Filter to mask sensitive data in logs"""
    
    def __init__(self):
        super().__init__()
        # Patterns to detect and mask sensitive data
        self.patterns = [
            # Credit card numbers with or without separators
            (re.compile(r'(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})'), r'\1-XXXX-XXXX-\4'),
            
            # Social security numbers
            (re.compile(r'(\d{3})-(\d{2})-(\d{4})'), r'\1-XX-\3'),
            
            # API keys, tokens, and secrets
            (re.compile(r'(api[-_]?key|token|secret)[:=]\s*[\'"]?([a-zA-Z0-9]{8,})[\'"]?', 
                      re.IGNORECASE), r'\1=XXXX'),
            
            # Bearer tokens in Authorization headers
            (re.compile(r'(Authorization:\s*Bearer\s+)([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)', 
                      re.IGNORECASE), r'\1XXXX'),
            
            # Email addresses
            (re.compile(r'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'), r'\1@XXXX'),
            
            # Passwords in various formats
            (re.compile(r'(password\s*[=:]\s*["\'])(.+?)(["\'])', re.IGNORECASE), r'\1XXXX\3'),
        ]
        
        # Fields to completely redact
        self.sensitive_fields = [
            'password', 'secret', 'token', 'apiKey', 'api_key', 'key',
            'creditCard', 'credit_card', 'ssn', 'social', 'credentials'
        ]

    def filter(self, record):
        # Apply to message if it's a string
        if isinstance(record.msg, str):
            for pattern, repl in self.patterns:
                record.msg = pattern.sub(repl, record.msg)
        
        # Apply to arguments if present
        if hasattr(record, 'args') and record.args:
            args_list = list(record.args)
            for i, arg in enumerate(args_list):
                if isinstance(arg, str):
                    for pattern, repl in self.patterns:
                        args_list[i] = pattern.sub(repl, arg)
                elif isinstance(arg, dict):
                    args_list[i] = self._filter_dict(arg)
            record.args = tuple(args_list)
        
        return True
    
    def _filter_dict(self, data):
        """Recursively filter dictionary values"""
        if not isinstance(data, dict):
            return data
            
        filtered = {}
        for key, value in data.items():
            # Check if this is a sensitive key
            if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = self._filter_dict(value)
            elif isinstance(value, list):
                filtered[key] = [self._filter_dict(item) if isinstance(item, dict) else item 
                                for item in value]
            elif isinstance(value, str):
                # Apply patterns to string values
                filtered_value = value
                for pattern, repl in self.patterns:
                    filtered_value = pattern.sub(repl, filtered_value)
                filtered[key] = filtered_value
            else:
                filtered[key] = value
                
        return filtered

# Setup the logger with the filter
logger = logging.getLogger("app")
logger.addFilter(SensitiveDataFilter())
```

### 3. Structured Logging Format
- I'll implement structured JSON logging
- I'll suggest standardized field naming
- I'll help create consistent timestamp formats
- I'll recommend correlation ID inclusion
- I'll provide context enrichment strategies

**Implementation Focus:**
```javascript
// Winston structured logging configuration for Node.js
const winston = require('winston');
const { format, createLogger, transports } = winston;
const { combine, timestamp, json, errors } = format;

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    // ISO timestamp with timezone
    timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    // Include stack traces for errors
    errors({ stack: true }),
    // Structured JSON output
    json()
  ),
  defaultMeta: { 
    service: 'payment-api', 
    environment: process.env.NODE_ENV || 'development',
  },
  transports: [
    new transports.Console(),
    new transports.File({ 
      filename: 'logs/app.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
    })
  ]
});

// Request context middleware for Express
function requestContextMiddleware(req, res, next) {
  // Generate or use provided correlation ID
  const correlationId = req.headers['x-correlation-id'] || uuidv4();
  
  // Add response header for correlation
  res.setHeader('x-correlation-id', correlationId);
  
  // Create child logger with request context
  req.logger = logger.child({
    correlationId,
    requestId: uuidv4(),
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user ? req.user.id : 'anonymous',
  });
  
  req.logger.info('Request received');
  
  // Track response time
  const start = Date.now();
  
  // Log response after completion
  res.on('finish', () => {
    const duration = Date.now() - start;
    req.logger.info('Request completed', {
      statusCode: res.statusCode,
      duration,
    });
  });
  
  next();
}
```

### 4. Compliance & Retention
- I'll help meet regulatory requirements (GDPR, HIPAA, PCI DSS, SOC2)
- I'll suggest appropriate retention policies
- I'll implement log rotation strategies
- I'll recommend secure log storage approaches
- I'll provide audit trail considerations

**Implementation Focus:**
```java
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class LogRetentionService {

    @Value("${log.retention.security.days:365}")  // 1 year for security logs (PCI DSS)
    private int securityLogRetentionDays;
    
    @Value("${log.retention.application.days:90}")  // 90 days for app logs
    private int appLogRetentionDays;
    
    @Value("${log.directory:/var/log/myapp}")
    private String logDirectory;
    
    @Value("${log.archive.directory:/var/log/myapp/archive}")
    private String archiveDirectory;
    
    /**
     * Scheduled job to manage log retention policy
     * Runs daily at 2:00 AM
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void enforceRetentionPolicy() {
        try {
            // Process security logs (retention based on compliance requirements)
            processLogRetention(
                Paths.get(logDirectory, "security"), 
                securityLogRetentionDays,
                "security"
            );
            
            // Process application logs
            processLogRetention(
                Paths.get(logDirectory, "application"), 
                appLogRetentionDays,
                "application"
            );
        } catch (IOException e) {
            // Log but don't fail the application
            logger.error("Failed to process log retention", e);
        }
    }
    
    private void processLogRetention(Path directory, int retentionDays, String logType) 
            throws IOException {
        
        if (!Files.exists(directory)) {
            logger.warn("Log directory does not exist: {}", directory);
            return;
        }
        
        LocalDate cutoffDate = LocalDate.now().minusDays(retentionDays);
        DateTimeFormatter datePattern = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        
        // Archive logs that have passed retention period
        try (Stream<Path> logFiles = Files.list(directory)) {
            logFiles
                .filter(Files::isRegularFile)
                .filter(path -> {
                    // Extract date from filename (format: logfile-2023-04-15.log)
                    String filename = path.getFileName().toString();
                    try {
                        // Extract date from filename pattern
                        int dateStartIdx = filename.indexOf('-') + 1;
                        int dateEndIdx = filename.lastIndexOf('.');
                        if (dateStartIdx > 0 && dateEndIdx > dateStartIdx) {
                            String dateStr = filename.substring(dateStartIdx, dateEndIdx);
                            LocalDate logDate = LocalDate.parse(dateStr, datePattern);
                            return logDate.isBefore(cutoffDate);
                        }
                        return false;
                    } catch (Exception e) {
                        logger.warn("Could not parse date from filename: {}", filename);
                        return false;
                    }
                })
                .forEach(path -> {
                    try {
                        // For security logs, archive them instead of deleting
                        if ("security".equals(logType)) {
                            Path archivePath = Paths.get(archiveDirectory, 
                                                        path.getFileName().toString());
                            Files.createDirectories(archivePath.getParent());
                            Files.move(path, archivePath);
                            logger.info("Archived security log: {}", path);
                        } else {
                            // For regular app logs, delete after retention period
                            Files.delete(path);
                            logger.info("Deleted expired log: {}", path);
                        }
                    } catch (IOException e) {
                        logger.error("Failed to process log file: {}", path, e);
                    }
                });
        }
    }
}
```

### 5. Log Transport & Analysis
- I'll suggest secure central log collection
- I'll implement log formatting for SIEM integration
- I'll recommend log aggregation approaches
- I'll help set up log alerts for security events
- I'll provide log correlation strategies

**Implementation Focus:**
```yaml
# Docker Compose setup for ELK stack log analysis
version: '3'
services:
  # Elasticsearch for log storage and indexing
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=secureElasticPassword
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - elk
    restart: unless-stopped
    
  # Logstash for log processing and filtering
  logstash:
    image: docker.elastic.co/logstash/logstash:7.14.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
      - ./logs:/logs
    environment:
      - "LS_JAVA_OPTS=-Xmx256m -Xms256m"
    networks:
      - elk
    depends_on:
      - elasticsearch
    restart: unless-stopped
    
  # Kibana for log visualization
  kibana:
    image: docker.elastic.co/kibana/kibana:7.14.0
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=secureElasticPassword
    networks:
      - elk
    depends_on:
      - elasticsearch
    restart: unless-stopped
    
  # Filebeat for secure log shipping
  filebeat:
    image: docker.elastic.co/beats/filebeat:7.14.0
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - ./logs:/logs:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - filebeat-data:/usr/share/filebeat/data
    user: root
    networks:
      - elk
    depends_on:
      - logstash
      - elasticsearch
    restart: unless-stopped

networks:
  elk:
    driver: bridge

volumes:
  elasticsearch-data:
  filebeat-data:
```

```yaml
# filebeat.yml - Secure log shipping configuration
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /logs/application/*.log
  fields:
    log_type: application
  fields_under_root: true
  json.keys_under_root: true
  json.overwrite_keys: true

- type: log
  enabled: true
  paths:
    - /logs/security/*.log
  fields:
    log_type: security
  fields_under_root: true
  json.keys_under_root: true
  json.overwrite_keys: true

processors:
  # Redact sensitive data patterns as an additional security layer
  - dissect:
      tokenizer: "%{timestamp} %{+timestamp} %{level} %{message}"
      field: "message"
      target_prefix: ""
  - script:
      lang: javascript
      source: >
        function process(event) {
          // Redact potential credit card numbers
          var ccRegex = /\b(?:\d{4}[- ]?){3}\d{4}\b/g;
          var fields = event.Get("message");
          if (fields) {
            event.Put("message", fields.replace(ccRegex, "XXXX-XXXX-XXXX-XXXX"));
          }
          return event;
        }

# Use secure TLS communication
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  protocol: "https"
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.crt"
  ssl.key: "/etc/filebeat/certs/filebeat.key"
  username: "filebeat_writer"
  password: "${FILEBEAT_PASSWORD}"
  indices:
    - index: "app-logs-%{+yyyy.MM.dd}"
      when.equals:
        log_type: "application"
    - index: "security-logs-%{+yyyy.MM.dd}"
      when.equals:
        log_type: "security"
```

### 6. Performance Considerations
- I'll implement asynchronous logging patterns
- I'll suggest appropriate log levels
- I'll help manage log volume and verbosity
- I'll recommend buffer and batch configurations
- I'll provide failsafe logging strategies

**Implementation Focus:**
```java
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-performance asynchronous logging wrapper
 * Uses a bounded queue and background thread for non-blocking logging
 */
public class AsyncSecurityLogger {
    private static final Logger logger = LoggerFactory.getLogger("security");
    private static final int QUEUE_CAPACITY = 10000;
    private static final BlockingQueue<LogEvent> eventQueue = 
            new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    private static final ExecutorService logProcessor = 
            Executors.newSingleThreadExecutor();
    private static final CircuitBreaker circuitBreaker = 
            new CircuitBreaker(5, 60000); // 5 failures within 60 seconds
    private static boolean isShutdown = false;
    
    static {
        // Start the background logging thread
        logProcessor.execute(() -> {
            while (!Thread.currentThread().isInterrupted() && !isShutdown) {
                try {
                    LogEvent event = eventQueue.poll(100, TimeUnit.MILLISECONDS);
                    if (event != null) {
                        try {
                            // Write the log entry
                            switch (event.getLevel()) {
                                case INFO:
                                    logger.info(event.getMessage(), event.getArgs());
                                    break;
                                case WARN:
                                    logger.warn(event.getMessage(), event.getArgs());
                                    break;
                                case ERROR:
                                    logger.error(event.getMessage(), event.getArgs());
                                    break;
                                case DEBUG:
                                    logger.debug(event.getMessage(), event.getArgs());
                                    break;
                            }
                            // Reset failure count on success
                            circuitBreaker.recordSuccess();
                        } catch (Exception e) {
                            // Record failure and handle based on circuit breaker
                            if (circuitBreaker.recordFailure()) {
                                // Log to fallback
                                System.err.println("Logging system failure: " + e.getMessage());
                                System.err.println("Original log: " + event.getMessage());
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            // Process remaining logs on shutdown
            drainQueue();
        });
        
        // Register shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shutdown();
        }));
    }
    
    /**
     * Asynchronously log an informational security event
     */
    public static void info(String message, Object... args) {
        if (logger.isInfoEnabled() && !isShutdown) {
            enqueue(new LogEvent(LogLevel.INFO, message, args));
        }
    }
    
    /**
     * Asynchronously log a warning security event
     */
    public static void warn(String message, Object... args) {
        if (logger.isWarnEnabled() && !isShutdown) {
            enqueue(new LogEvent(LogLevel.WARN, message, args));
        }
    }
    
    /**
     * Asynchronously log an error security event
     */
    public static void error(String message, Object... args) {
        if (logger.isErrorEnabled() && !isShutdown) {
            enqueue(new LogEvent(LogLevel.ERROR, message, args));
        }
    }
    
    /**
     * Asynchronously log a debug security event
     */
    public static void debug(String message, Object... args) {
        if (logger.isDebugEnabled() && !isShutdown) {
            enqueue(new LogEvent(LogLevel.DEBUG, message, args));
        }
    }
    
    private static void enqueue(LogEvent event) {
        // If circuit is open, write to fallback
        if (circuitBreaker.isOpen()) {
            System.err.println("Logging circuit open, writing to fallback: " + event.getMessage());
            return;
        }
        
        // Try to add to queue, drop if full
        boolean added = eventQueue.offer(event);
        if (!added) {
            // Queue is full, log to fallback
            System.err.println("Logging queue full, dropping log: " + event.getMessage());
        }
    }
    
    /**
     * Graceful shutdown, processes remaining logs
     */
    public static void shutdown() {
        isShutdown = true;
        
        try {
            // Wait for logs to be processed
            logProcessor.shutdown();
            logProcessor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            // Force shutdown if still running
            if (!logProcessor.isTerminated()) {
                logProcessor.shutdownNow();
                drainQueue();
            }
        }
    }
    
    /**
     * Process remaining logs directly
     */
    private static void drainQueue() {
        LogEvent event;
        while ((event = eventQueue.poll()) != null) {
            try {
                switch (event.getLevel()) {
                    case INFO:
                        logger.info(event.getMessage(), event.getArgs());
                        break;
                    case WARN:
                        logger.warn(event.getMessage(), event.getArgs());
                        break;
                    case ERROR:
                        logger.error(event.getMessage(), event.getArgs());
                        break;
                    case DEBUG:
                        logger.debug(event.getMessage(), event.getArgs());
                        break;
                }
            } catch (Exception e) {
                // Fallback direct logging
                System.err.println("Failed to process remaining log: " + event.getMessage());
            }
        }
    }
    
    /**
     * Log event container
     */
    private static class LogEvent {
        private final LogLevel level;
        private final String message;
        private final Object[] args;
        
        public LogEvent(LogLevel level, String message, Object[] args) {
            this.level = level;
            this.message = message;
            this.args = args;
        }
        
        public LogLevel getLevel() { return level; }
        public String getMessage() { return message; }
        public Object[] getArgs() { return args; }
    }
    
    private enum LogLevel {
        DEBUG, INFO, WARN, ERROR
    }
    
    /**
     * Simple circuit breaker for logging system
     */
    private static class CircuitBreaker {
        private final int failureThreshold;
        private final long resetTimeoutMs;
        private int failureCount;
        private long lastFailureTime;
        private boolean open;
        
        public CircuitBreaker(int failureThreshold, long resetTimeoutMs) {
            this.failureThreshold = failureThreshold;
            this.resetTimeoutMs = resetTimeoutMs;
            this.failureCount = 0;
            this.lastFailureTime = 0;
            this.open = false;
        }
        
        public synchronized boolean isOpen() {
            // Check if circuit should be reset based on timeout
            if (open && System.currentTimeMillis() - lastFailureTime > resetTimeoutMs) {
                // Try to close the circuit
                open = false;
                failureCount = 0;
            }
            return open;
        }
        
        public synchronized boolean recordFailure() {
            failureCount++;
            lastFailureTime = System.currentTimeMillis();
            
            if (failureCount >= failureThreshold) {
                open = true;
            }
            
            return open;
        }
        
        public synchronized void recordSuccess() {
            if (!open) {
                failureCount = 0;
            }
        }
    }
}
```

### 7. Error & Exception Handling
- I'll implement secure exception logging
- I'll suggest error classification strategies
- I'll help avoid information disclosure
- I'll provide stack trace handling best practices
- I'll recommend error correlation approaches

**Implementation Focus:**
```typescript
import { createLogger, format, transports } from 'winston';
import { NextFunction, Request, Response } from 'express';

// Create application logger
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'api-service' },
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/error.log', level: 'error' }),
    new transports.File({ filename: 'logs/combined.log' })
  ]
});

// Error types for classification
enum ErrorType {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  DATABASE = 'DATABASE',
  EXTERNAL_SERVICE = 'EXTERNAL_SERVICE',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  SYSTEM = 'SYSTEM'
}

// Base error class with classification and safe message handling
class AppError extends Error {
  public readonly type: ErrorType;
  public readonly isOperational: boolean;
  public readonly errorId: string;
  public readonly safe: boolean;
  public readonly statusCode: number;
  private readonly sensitiveInfo: Record<string, any>;
  
  constructor(
    message: string, 
    type: ErrorType = ErrorType.SYSTEM,
    statusCode: number = 500, 
    isOperational: boolean = true,
    sensitiveInfo: Record<string, any> = {},
    safe: boolean = false
  ) {
    // User-facing message - sanitize to avoid information disclosure
    super(safe ? message : 'An unexpected error occurred');
    
    this.type = type;
    this.isOperational = isOperational;
    this.errorId = generateErrorId(); // UUID or other unique identifier
    this.safe = safe;
    this.statusCode = statusCode;
    this.sensitiveInfo = sensitiveInfo; // Not exposed to users
    
    Error.captureStackTrace(this, this.constructor);
  }
  
  // For internal logging only - includes sensitive details
  public getFullErrorDetails(): Record<string, any> {
    return {
      message: this.message,
      type: this.type,
      errorId: this.errorId,
      stack: this.stack,
      isOperational: this.isOperational,
      ...this.sensitiveInfo
    };
  }
  
  // For client responses - no sensitive information
  public getPublicError(): Record<string, any> {
    return {
      message: this.safe ? this.message : 'An unexpected error occurred',
      errorId: this.errorId,
      type: this.type
    };
  }
}

// Specific error types
class ValidationError extends AppError {
  constructor(message: string, details?: Record<string, any>) {
    super(
      message,
      ErrorType.VALIDATION,
      400,
      true,
      { validationDetails: details },
      true // Validation errors are generally safe to show to users
    );
  }
}

class AuthenticationError extends AppError {
  constructor(message: string, details?: Record<string, any>) {
    super(
      'Authentication failed',
      ErrorType.AUTHENTICATION,
      401,
      true,
      { authDetails: details },
      false // Don't show specific auth failure reasons
    );
  }
}

// Global error handler middleware
export function errorHandler(
  err: Error, 
  req: Request, 
  res: Response, 
  next: NextFunction
): void {
  // Default error structure if not an AppError
  let error = err;
  
  if (!(err instanceof AppError)) {
    error = new AppError(
      'An unexpected error occurred',
      ErrorType.SYSTEM,
      500,
      false,
      { originalError: err.message }
    );
  }
  
  const appError = error as AppError;
  
  // Log the full error details (including sensitive info) for internal use
  logger.error('Application error', {
    ...appError.getFullErrorDetails(),
    path: req.path,
    method: req.method,
    correlationId: req.headers['x-correlation-id'] || 'unknown',
    userId: req.user?.id || 'anonymous',
  });
  
  // Send sanitized response to client
  res.status(appError.statusCode).json({
    success: false,
    ...appError.getPublicError()
  });
}

// Utility function to generate unique error IDs
function generateErrorId(): string {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
}
```

## Output Format

When providing secure logging recommendations, I will:

1. **Analyze Requirements** - Determine logging needs based on application type, sensitivity, and compliance requirements
2. **Provide Implementation Guidance** - Suggest appropriate logging frameworks, configurations, and patterns
3. **Include Code Examples** - Provide working examples showing best practices in the relevant language/framework
4. **Address Security Concerns** - Highlight sensitive data handling, secure storage, and access controls
5. **Consider Performance** - Balance security needs with application performance requirements

**Example Structure:**
```markdown
## Secure Logging Analysis

Your Flask healthcare application needs logging that:
- Protects PHI and PII in logs (HIPAA compliance)
- Creates comprehensive audit trails for access events
- Supports security incident investigation
- Provides structured logs for SIEM integration

## Implementation Approach

I recommend implementing a layered logging strategy with:

1. **Structured JSON logging** for machine readability
2. **Separate security event logs** for audit purposes
3. **Sensitive data filtering** to prevent PHI exposure
4. **Correlation IDs** to track requests across system components
5. **SIEM-compatible formatting** for security monitoring integration

## Python Implementation

Here's a secure logging setup for your Flask application:

```python
import logging
import json
from flask import request, g
from datetime import datetime
import uuid
import re

class PHISafeJsonFormatter(logging.Formatter):
    """JSON formatter that redacts PHI/PII"""
    
    def __init__(self):
        super().__init__()
        self.phi_patterns = [
            # Patterns to match PHI/PII
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
            re.compile(r'\b\d{10,16}\b'),          # MRN/Patient IDs
            # Additional patterns...
        ]
    
    def format(self, record):
        log_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': self._redact_phi(record.getMessage()),
            'logger': record.name,
            'path': getattr(g, 'request_path', ''),
            'method': getattr(g, 'request_method', ''),
            'correlation_id': getattr(g, 'correlation_id', ''),
            'user_id': getattr(g, 'user_id', 'anonymous'),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_record['exception'] = self._redact_phi(
                self.formatException(record.exc_info)
            )
        
        return json.dumps(log_record)
    
    def _redact_phi(self, text):
        if not text:
            return text
            
        result = text
        for pattern in self.phi_patterns:
            result = pattern.sub('[REDACTED]', result)
        return result

# Setup handlers
def configure_logging():
    # Application logger
    app_handler = logging.FileHandler('logs/app.log')
    app_handler.setFormatter(PHISafeJsonFormatter())
    app_logger = logging.getLogger('app')
    app_logger.setLevel(logging.INFO)
    app_logger.addHandler(app_handler)
    
    # Security events logger (separate file for audit purposes)
    security_handler = logging.FileHandler('logs/security.log')
    security_handler.setFormatter(PHISafeJsonFormatter())
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    
    return app_logger, security_logger

app_logger, security_logger = configure_logging()

# Flask request middleware
@app.before_request
def before_request():
    g.start_time = datetime.utcnow()
    g.correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
    g.request_path = request.path
    g.request_method = request.method
    
    # Set user ID if authenticated
    if hasattr(g, 'user') and g.user:
        g.user_id = g.user.id
    else:
        g.user_id = 'anonymous'
    
    # Add correlation ID to response
    @app.after_request
    def add_correlation_id(response):
        response.headers['X-Correlation-ID'] = g.correlation_id
        return response
```

## Security Features

1. **PHI Protection**: Regex patterns redact sensitive health information
2. **Structured Format**: JSON logs are easily parsed by SIEM systems
3. **Correlation ID**: Every request gets a unique ID for tracing
4. **Separate Security Logs**: Security events logged separately for audit
5. **HIPAA Considerations**: Logging design supports compliance requirements

## Recommendations

1. Store logs in encrypted storage with access controls
2. Implement log rotation with 6-year retention (HIPAA requirement)
3. Set up real-time monitoring for security event logs
4. Create a log review process for periodic audit
5. Test PHI redaction thoroughly with sample data
```
