# GitHub Copilot Custom Instructions for Content Training Review

## General Instructions

As GitHub Copilot, I'll help you implement secure content review systems for AI training data. I'll proactively identify potential security and safety issues in content filtering systems, suggest best practices for content moderation, and help you build robust, multi-layered approaches to detect harmful or inappropriate AI training materials.

## Security Considerations for Content Review Systems

When suggesting code for content review systems, I will prioritize these security aspects:

### 1. Multi-Layer Content Classification
- I'll suggest comprehensive classification taxonomies
- I'll recommend implementing multiple detection methods
- I'll suggest confidence thresholds and decision logic
- I'll propose effective filter strength configuration
- I'll recommend proper handling of edge cases

**Implementation Focus:**
```python
# Multi-layered content classification system
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re

class ContentClassifier:
    def __init__(self):
        # Layer 1: Pattern-based detection (fast, high precision)
        self.patterns = {
            "explicit_content": [r'\b(explicit terms)\b', r'\b(offensive words)\b'],
            "pii": [r'\b\d{3}-\d{2}-\d{4}\b', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b']
        }
        
        # Layer 2: Transformer-based classification (slower, more nuanced)
        self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        self.model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased-finetuned-sst-2-english")
        
        # Layer 3: Ensemble voting system
        self.threshold = {
            "high_confidence": 0.8,
            "medium_confidence": 0.6,
            "low_confidence": 0.4
        }
    
    def classify(self, content):
        results = {
            "pattern_matches": self._pattern_match(content),
            "transformer_scores": self._transformer_classify(content),
        }
        
        # Decision logic combining multiple signals
        final_decision = self._make_decision(results)
        
        # Add confidence level
        confidence = self._calculate_confidence(results)
        
        return {
            "decision": final_decision,
            "confidence": confidence,
            "details": results,
            "needs_human_review": confidence < self.threshold["medium_confidence"]
        }
    
    def _pattern_match(self, content):
        matches = {}
        for category, patterns in self.patterns.items():
            matches[category] = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    matches[category].extend(found)
        return matches
    
    def _transformer_classify(self, content):
        # Truncate content if needed
        max_length = self.tokenizer.model_max_length
        encoded = self.tokenizer(content, truncation=True, max_length=max_length, return_tensors="pt")
        
        # Get model predictions
        with torch.no_grad():
            outputs = self.model(**encoded)
            scores = torch.softmax(outputs.logits, dim=1).numpy()[0]
        
        return {
            "positive": float(scores[1]),
            "negative": float(scores[0])
        }
    
    def _make_decision(self, results):
        # Check for pattern matches first (high precision)
        if any(len(matches) > 0 for category, matches in results["pattern_matches"].items()):
            return "flagged"
            
        # Check transformer scores
        if results["transformer_scores"]["negative"] > self.threshold["high_confidence"]:
            return "flagged"
        elif results["transformer_scores"]["negative"] > self.threshold["medium_confidence"]:
            return "needs_review"
        else:
            return "approved"
    
    def _calculate_confidence(self, results):
        # Simple confidence calculation - combine signals
        pattern_confidence = 1.0 if any(len(matches) > 0 for category, matches in results["pattern_matches"].items()) else 0.0
        transformer_confidence = results["transformer_scores"]["negative"]
        
        # Weighted average of confidences
        return max(pattern_confidence, transformer_confidence)
```

### 2. Harmful Content Detection & Privacy Protection
- I'll suggest techniques to detect harmful, misleading, or inappropriate content
- I'll recommend PII detection and handling methods
- I'll suggest ways to balance sensitivity with false positives
- I'll propose methods for content provenance tracking
- I'll recommend secure audit logging for review decisions

**Implementation Focus:**
```python
# PII detection and redaction with secure logging
import re
import hashlib
import logging
from datetime import datetime
import json

class PIIHandler:
    def __init__(self, log_path="./secure_logs/"):
        # PII detection patterns
        self.pii_patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "ssn": r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
            "phone": r'\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b',
            "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            "address": r'\b\d{1,5}\s[A-Z][a-z]+\s[A-Za-z]+\b'
        }
        
        # Set up secure logging
        self.logger = self._setup_secure_logger(log_path)
        
    def _setup_secure_logger(self, log_path):
        logger = logging.getLogger("pii_handler")
        logger.setLevel(logging.INFO)
        
        # Create secure log handler with proper permissions
        import os
        os.makedirs(log_path, exist_ok=True)
        
        # Use rotating file handler to prevent log file from growing too large
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler(
            f"{log_path}/pii_events.log",
            maxBytes=10485760,  # 10MB
            backupCount=5,
            mode='a'
        )
        
        # Format with timestamp but WITHOUT the PII itself
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def detect_pii(self, text):
        """Detect PII in text and return findings without exposing the PII"""
        findings = {}
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # Only store count and hashed representations, not the PII itself
                findings[pii_type] = {
                    "count": len(matches),
                    "hashed_samples": [self._hash_pii(match) for match in matches[:3]]  # Limit samples
                }
        
        # Log the detection event securely
        if findings:
            self._log_detection_event(findings)
            
        return findings
    
    def redact_pii(self, text):
        """Redact PII from text"""
        redacted_text = text
        findings = {}
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[pii_type] = len(matches)
                
                # Replace each match with a redaction marker
                for match in matches:
                    redaction = f"[REDACTED_{pii_type}]"
                    redacted_text = redacted_text.replace(match, redaction)
        
        # Log the redaction event
        if findings:
            self._log_redaction_event(findings)
            
        return {
            "redacted_text": redacted_text,
            "pii_found": findings
        }
    
    def _hash_pii(self, pii_string):
        """Create a secure hash of PII for reference without storing the actual value"""
        # Use a salt for additional security
        salt = "FixedSaltForConsistency"  # In production, use a secure, stored salt
        return hashlib.sha256((pii_string + salt).encode()).hexdigest()[:16]
    
    def _log_detection_event(self, findings):
        """Log PII detection without including actual PII"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "pii_detection",
            "findings": {
                pii_type: count["count"] for pii_type, count in findings.items()
            }
        }
        
        self.logger.info(f"PII detected: {json.dumps(event)}")
    
    def _log_redaction_event(self, findings):
        """Log PII redaction without including actual PII"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "pii_redaction",
            "redaction_counts": findings
        }
        
        self.logger.info(f"PII redacted: {json.dumps(event)}")
```

### 3. Bias Detection & Cultural Sensitivity
- I'll suggest methods for detecting bias in training content
- I'll recommend cultural and contextual sensitivity checks
- I'll propose intersectional analysis approaches
- I'll suggest balancing techniques for training datasets
- I'll recommend monitoring for underrepresented groups

**Implementation Focus:**
```python
# Bias detection and analysis in content
import pandas as pd
import numpy as np
from collections import Counter

class BiasAnalyzer:
    def __init__(self, sensitive_attributes=None):
        # Define sensitive attributes to monitor
        self.sensitive_attributes = sensitive_attributes or {
            "gender": ["male", "female", "non-binary", "transgender"],
            "race": ["asian", "black", "hispanic", "white", "indigenous"],
            "religion": ["buddhist", "christian", "hindu", "jewish", "muslim"],
            "age": ["child", "teen", "young adult", "middle-aged", "senior"],
            "disability": ["blind", "deaf", "mobility impaired", "neurodivergent"]
        }
        
        # Load word association dictionaries
        self.associations = self._load_association_dictionaries()
        
        # Initialize metrics tracking
        self.metrics = {
            "representation": {},
            "sentiment": {},
            "stereotyping": {},
            "intersectional": {}
        }
    
    def analyze_dataset(self, texts, metadata=None):
        """Analyze a dataset of texts for potential bias"""
        results = {
            "representation": self._analyze_representation(texts),
            "sentiment": self._analyze_sentiment_associations(texts),
            "stereotyping": self._analyze_stereotypical_associations(texts)
        }
        
        # Add intersectional analysis if metadata is provided
        if metadata:
            results["intersectional"] = self._analyze_intersectional(texts, metadata)
        
        # Generate recommendations based on findings
        results["recommendations"] = self._generate_recommendations(results)
        
        return results
    
    def _analyze_representation(self, texts):
        """Analyze representation of different groups in the dataset"""
        # Join all texts for overall analysis
        all_text = " ".join(texts).lower()
        
        representation = {}
        
        # Count mentions of each attribute
        for category, terms in self.sensitive_attributes.items():
            category_counts = {}
            for term in terms:
                # Count occurrences, considering word boundaries
                count = len(re.findall(r'\b' + term + r'\b', all_text))
                if count > 0:
                    category_counts[term] = count
            
            if category_counts:
                total = sum(category_counts.values())
                representation[category] = {
                    "counts": category_counts,
                    "distribution": {k: v/total for k, v in category_counts.items()},
                    "total": total
                }
        
        # Calculate distribution skew
        for category, data in representation.items():
            if len(data["distribution"]) > 1:
                values = list(data["distribution"].values())
                expected = 1.0 / len(values)  # Equal distribution
                
                # Calculate deviation from equal distribution
                max_deviation = max([abs(v - expected) for v in values])
                data["skew"] = max_deviation / expected
        
        return representation
    
    def _analyze_sentiment_associations(self, texts):
        """Analyze sentiment associated with different groups"""
        # This would use sentiment analysis - simplified implementation
        sentiment_results = {}
        
        # For each category of sensitive attributes
        for category, terms in self.sensitive_attributes.items():
            category_sentiment = {}
            
            # For each text, check sentiment around mentions of terms
            for term in terms:
                # Placeholder for real sentiment analysis
                # In production, use window around term mentions to calculate sentiment
                sentiment_score = 0.0  # Placeholder
                if sentiment_score != 0:
                    category_sentiment[term] = sentiment_score
            
            if category_sentiment:
                sentiment_results[category] = category_sentiment
        
        return sentiment_results
    
    def _analyze_stereotypical_associations(self, texts):
        """Analyze stereotypical associations in the texts"""
        # This would check for stereotypical associations - simplified implementation
        stereotype_results = {}
        
        # Check for common stereotypical associations
        for category, associations in self.associations.items():
            category_stereotypes = {}
            
            for term, stereotype_patterns in associations.items():
                # Count stereotypical associations
                # In production, use more sophisticated NLP techniques
                stereotype_count = 0  # Placeholder
                if stereotype_count > 0:
                    category_stereotypes[term] = stereotype_count
            
            if category_stereotypes:
                stereotype_results[category] = category_stereotypes
        
        return stereotype_results
    
    def _analyze_intersectional(self, texts, metadata):
        """Analyze intersectional patterns if metadata is available"""
        # This would examine intersectional effects - simplified implementation
        intersectional_results = {}
        
        # Placeholder for real intersectional analysis
        # In production, this would analyze how multiple attributes interact
        
        return intersectional_results
    
    def _generate_recommendations(self, results):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        # Check representation issues
        for category, data in results["representation"].items():
            if "skew" in data and data["skew"] > 0.5:  # Significant skew
                recommendations.append({
                    "type": "representation_imbalance",
                    "category": category,
                    "description": f"Significant imbalance in {category} representation",
                    "suggestion": "Consider adding more diverse content to balance representation"
                })
        
        # Check sentiment bias
        for category, data in results["sentiment"].items():
            # Look for sentiment differences
            values = list(data.values())
            if values and (max(values) - min(values)) > 0.5:
                recommendations.append({
                    "type": "sentiment_bias",
                    "category": category,
                    "description": f"Potential sentiment bias for {category} attributes",
                    "suggestion": "Review and balance sentiment associations across groups"
                })
        
        # Check stereotypical associations
        if results["stereotyping"]:
            for category in results["stereotyping"]:
                recommendations.append({
                    "type": "stereotyping",
                    "category": category,
                    "description": f"Potential stereotypical associations for {category}",
                    "suggestion": "Review and revise content to avoid reinforcing stereotypes"
                })
        
        return recommendations
    
    def _load_association_dictionaries(self):
        """Load dictionaries of stereotypical associations"""
        # In production, these would be more comprehensive
        return {
            "gender": {
                "male": ["strong", "aggressive", "logical"],
                "female": ["emotional", "nurturing", "gentle"]
            },
            "profession": {
                "doctor": ["male", "he"],
                "nurse": ["female", "she"],
                "engineer": ["male", "he"]
            }
        }
```

### 4. Workflow & Human-in-the-Loop Systems
- I'll suggest effective content moderation workflows
- I'll recommend human-in-the-loop review processes
- I'll propose decision escalation pathways
- I'll suggest proper reviewer tools and interfaces
- I'll recommend feedback loops for system improvement

**Implementation Focus:**
```typescript
// Human-in-the-loop review workflow in TypeScript
import { useState, useEffect } from 'react';
import axios from 'axios';

// Content review types
interface ContentItem {
  id: string;
  text: string;
  metadata: Record<string, any>;
  aiReview: {
    decision: 'approve' | 'reject' | 'needs_review';
    confidence: number;
    flags: Record<string, number>;
  };
  status: 'pending' | 'approved' | 'rejected' | 'modified';
  assignedTo?: string;
  priority: 'high' | 'medium' | 'low';
}

interface ReviewDecision {
  contentId: string;
  decision: 'approve' | 'reject' | 'modify';
  modifiedContent?: string;
  flags: string[];
  notes: string;
  reviewerId: string;
}

// Content review workflow hook
export function useContentReviewWorkflow(reviewerId: string) {
  const [queue, setQueue] = useState<ContentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<Record<string, any>>({});
  
  // Load review queue
  const loadReviewQueue = async () => {
    try {
      setLoading(true);
      
      // Get reviewer's assigned content with proper authentication
      const response = await axios.get('/api/content-review/queue', {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
        },
        params: {
          reviewerId,
          status: 'pending',
          limit: 20
        }
      });
      
      setQueue(response.data.items || []);
      setStats(response.data.stats || {});
      
    } catch (error) {
      console.error('Error loading content review queue:', error);
      // Implement proper error handling
    } finally {
      setLoading(false);
    }
  };
  
  // Submit a review decision
  const submitReview = async (decision: ReviewDecision): Promise<boolean> => {
    try {
      // Log review action for audit trail (non-sensitive info only)
      console.log(`Submitting ${decision.decision} for content ${decision.contentId}`);
      
      // Submit the review with proper authentication
      const response = await axios.post('/api/content-review/decisions', decision, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
          'X-CSRF-Token': getCsrfToken() // CSRF protection
        }
      });
      
      // Update local queue
      setQueue(queue.filter(item => item.id !== decision.contentId));
      
      // Track review metrics
      trackReviewMetric(decision.decision);
      
      return true;
    } catch (error) {
      console.error('Error submitting review decision:', error);
      // Implement proper error handling and retry logic
      return false;
    }
  };
  
  // Escalate difficult cases
  const escalateContent = async (contentId: string, reason: string): Promise<boolean> => {
    try {
      await axios.post('/api/content-review/escalate', {
        contentId,
        reason,
        reviewerId
      }, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
          'X-CSRF-Token': getCsrfToken()
        }
      });
      
      // Update local queue
      setQueue(queue.filter(item => item.id !== contentId));
      
      return true;
    } catch (error) {
      console.error('Error escalating content:', error);
      return false;
    }
  };
  
  // Request another reviewer's opinion
  const requestSecondOpinion = async (contentId: string, note: string): Promise<boolean> => {
    try {
      await axios.post('/api/content-review/second-opinion', {
        contentId,
        note,
        requestedBy: reviewerId
      }, {
        headers: {
          'Authorization': `Bearer ${getAuthToken()}`,
          'X-CSRF-Token': getCsrfToken()
        }
      });
      
      // Mark as pending second opinion in local queue
      setQueue(queue.map(item => 
        item.id === contentId 
          ? { ...item, status: 'pending_second_opinion' as any } 
          : item
      ));
      
      return true;
    } catch (error) {
      console.error('Error requesting second opinion:', error);
      return false;
    }
  };
  
  // Load queue on initial render
  useEffect(() => {
    loadReviewQueue();
    
    // Refresh queue periodically
    const intervalId = setInterval(loadReviewQueue, 5 * 60 * 1000); // Every 5 minutes
    
    return () => clearInterval(intervalId);
  }, [reviewerId]);
  
  return {
    queue,
    loading,
    stats,
    submitReview,
    escalateContent,
    requestSecondOpinion,
    refreshQueue: loadReviewQueue
  };
}

// Helper functions
function getAuthToken(): string {
  // Get token from secure storage
  return localStorage.getItem('auth_token') || '';
}

function getCsrfToken(): string {
  // Get CSRF token from meta tag
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

function trackReviewMetric(decision: string): void {
  // Track metrics for reporting and system improvement
  const metrics = JSON.parse(localStorage.getItem('review_metrics') || '{}');
  metrics[decision] = (metrics[decision] || 0) + 1;
  localStorage.setItem('review_metrics', JSON.stringify(metrics));
}
```

### 5. Audit & Compliance Features
- I'll suggest comprehensive audit trail implementation
- I'll recommend secure logging practices
- I'll propose content provenance tracking
- I'll suggest compliance documentation approaches
- I'll recommend secure reviewer access controls

**Implementation Focus:**
```typescript
// Secure audit logging system in TypeScript
import winston from 'winston';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

interface AuditEvent {
  eventId: string;
  timestamp: string;
  eventType: string;
  userId: string;
  action: string;
  resourceId?: string;
  resourceType?: string;
  details: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

class SecureAuditLogger {
  private logger: winston.Logger;
  private cryptoKey: Buffer;
  private cryptoIV: Buffer;
  
  constructor(options: {
    logDirectory: string;
    encryptLogs: boolean;
    encryptionKey?: string;
    rotationDays?: number;
  }) {
    // Create log directory if it doesn't exist
    if (!fs.existsSync(options.logDirectory)) {
      fs.mkdirSync(options.logDirectory, { recursive: true });
    }
    
    // Set up encryption if enabled
    if (options.encryptLogs) {
      if (!options.encryptionKey) {
        throw new Error('Encryption key is required when encryption is enabled');
      }
      
      // Derive key and IV from the provided encryption key
      const keyMaterial = crypto.createHash('sha256').update(options.encryptionKey).digest();
      this.cryptoKey = keyMaterial.slice(0, 32); // Use first 32 bytes for key
      this.cryptoIV = keyMaterial.slice(32, 48);  // Use next 16 bytes for IV
    }
    
    // Set up Winston logger
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
        // Custom format to encrypt logs if enabled
        winston.format((info) => {
          if (options.encryptLogs) {
            const plaintext = JSON.stringify(info);
            info.encrypted = this.encryptData(plaintext);
            // Remove original fields except metadata
            Object.keys(info).forEach(key => {
              if (!['level', 'encrypted', 'timestamp'].includes(key)) {
                delete info[key];
              }
            });
          }
          return info;
        })()
      ),
      transports: [
        // Log to file with daily rotation
        new winston.transports.File({
          filename: path.join(options.logDirectory, 'audit.log'),
          maxsize: 10485760, // 10MB
          maxFiles: options.rotationDays || 30,
          tailable: true
        }),
        // Also output to tamper-evident log
        new winston.transports.File({
          filename: path.join(options.logDirectory, 'audit-secure.log'),
          maxsize: 10485760, // 10MB
          maxFiles: options.rotationDays || 30,
          tailable: true,
          // Add hash chaining for tamper evidence
          format: winston.format((info) => {
            // Add hash of previous log entry + current log
            const prevHash = this.getLastLogHash();
            const currentData = JSON.stringify(info);
            info.hash = this.hashData(prevHash + currentData);
            return info;
          })()
        })
      ]
    });
  }
  
  public logAuditEvent(event: AuditEvent): void {
    // Generate unique event ID if not provided
    if (!event.eventId) {
      event.eventId = crypto.randomUUID();
    }
    
    // Ensure timestamp is set
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString();
    }
    
    // Remove any sensitive data from details
    const sanitizedDetails = this.sanitizeDetails(event.details);
    
    // Log the audit event
    this.logger.info({
      eventId: event.eventId,
      timestamp: event.timestamp,
      eventType: event.eventType,
      userId: event.userId,
      action: event.action,
      resourceId: event.resourceId,
      resourceType: event.resourceType,
      details: sanitizedDetails,
      ipAddress: this.anonymizeIP(event.ipAddress),
      userAgent: event.userAgent
    });
  }
  
  public logContentReview(reviewData: {
    contentId: string;
    reviewerId: string;
    decision: string;
    previousDecision?: string;
    flags?: string[];
    confidence?: number;
  }): void {
    this.logAuditEvent({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      eventType: 'content_review',
      userId: reviewData.reviewerId,
      action: 'review_decision',
      resourceId: reviewData.contentId,
      resourceType: 'content',
      details: {
        decision: reviewData.decision,
        previousDecision: reviewData.previousDecision,
        flags: reviewData.flags,
        confidence: reviewData.confidence
      }
    });
  }
  
  public logSystemEvent(eventData: {
    eventType: string;
    action: string;
    userId: string;
    details: Record<string, any>;
  }): void {
    this.logAuditEvent({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      eventType: eventData.eventType,
      userId: eventData.userId,
      action: eventData.action,
      details: eventData.details
    });
  }
  
  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sensitiveFields = ['password', 'token', 'secret', 'credit_card', 'ssn', 'content'];
    const sanitized = { ...details };
    
    // Recursively check for sensitive fields
    const sanitizeObject = (obj: Record<string, any>): void => {
      Object.keys(obj).forEach(key => {
        // Check if the key name contains any sensitive field names
        if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      });
    };
    
    sanitizeObject(sanitized);
    return sanitized;
  }
  
  private anonymizeIP(ip?: string): string | undefined {
    if (!ip) return undefined;
    
    // Anonymize IPv4 address by zeroing last octet
    // Example: 192.168.1.123 -> 192.168.1.0
    return ip.replace(/(\d+\.\d+\.\d+\.)\d+/, '$10');
  }
  
  private encryptData(data: string): string {
    const cipher = crypto.createCipheriv('aes-256-cbc', this.cryptoKey, this.cryptoIV);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
  }
  
  private hashData(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  private getLastLogHash(): string {
    // This would read the last log entry hash from the secure log file
    // Simplified implementation - in production, this would actually read the file
    return '0000000000000000000000000000000000000000000000000000000000000000';
  }
}

// Usage example
const auditLogger = new SecureAuditLogger({
  logDirectory: '/secure/logs/audit',
  encryptLogs: true,
  encryptionKey: process.env.AUDIT_ENCRYPTION_KEY,
  rotationDays: 90
});

// Log content review event
auditLogger.logContentReview({
  contentId: '12345',
  reviewerId: 'reviewer-789',
  decision: 'approved',
  previousDecision: 'needs_review',
  flags: ['potential_bias', 'political_content'],
  confidence: 0.85
});

// Log system event
auditLogger.logSystemEvent({
  eventType: 'system',
  action: 'filter_update',
  userId: 'admin-456',
  details: {
    filterType: 'harmful_content',
    updatedCategories: ['violence', 'harassment'],
    thresholds: { high: 0.8, medium: 0.6 }
  }
});
```

## Best Practices I'll Encourage

1. **Multi-Layered Filtering**: Implement multiple content detection methods
2. **Human Review Oversight**: Maintain human oversight for edge cases
3. **Regular Filter Updates**: Continuously improve detection capabilities
4. **Provenance Tracking**: Track content origins and modification history
5. **Confidence Scoring**: Use confidence metrics to prioritize human review
6. **Secure Audit Trails**: Maintain comprehensive review logs
7. **Bias Detection**: Implement checks for representation and stereotyping
8. **PII Protection**: Detect and handle personal information securely
9. **Cultural Context**: Consider regional and cultural variations in content appropriateness
10. **Feedback Loops**: Incorporate reviewer feedback to improve automated systems

## Anti-patterns I'll Help You Avoid

1. ❌ Relying solely on keyword filtering (too simplistic)
2. ❌ Using black-box models without explainability
3. ❌ Storing sensitive/inappropriate content unnecessarily
4. ❌ Neglecting cultural context in content moderation
5. ❌ Insufficient handling of edge cases
6. ❌ Inadequate reviewer training and support
7. ❌ Weak audit trails and accountability
8. ❌ Insufficient privacy controls for reviewers
9. ❌ Treating content moderation as purely technical (it's socio-technical)
10. ❌ Static filter rules that don't adapt to new challenges

## Testing Recommendations

I'll suggest incorporating these testing practices:

1. **Adversarial Testing**: Challenge filters with evasion techniques
2. **Bias Evaluation**: Test for demographic and representational fairness
3. **False Positive Analysis**: Evaluate mistaken content flagging rates
4. **Human Evaluation**: Regular audits by human reviewers
5. **Performance Testing**: Verify system under high-volume conditions
