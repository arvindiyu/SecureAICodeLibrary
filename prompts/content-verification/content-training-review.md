# Secure Coding Prompt: Content Training Review

## Purpose

This prompt guides you in implementing secure practices for reviewing AI model training content to identify and mitigate risks. Use this prompt to create robust content review systems that can detect harmful, misleading, or inappropriate training materials before they impact AI model behavior.

## Content Training Review Prompt

```
As a content safety expert, help me implement [CONTENT REVIEW FUNCTIONALITY] for AI training data with security and safety as priorities.

Consider these content safety aspects in your implementation:
1. Content classification and filtering
2. Harmful content detection
3. Bias identification and mitigation
4. PII and sensitive data identification
5. Content authenticity verification
6. Cultural and contextual sensitivity
7. Regulatory compliance
8. Content moderation workflow
9. Human-in-the-loop review processes
10. Audit trails and documentation

Technical requirements:
- Content types: [text, images, audio, video, etc.]
- AI model purpose: [generative AI, classification, recommendation, etc.]
- Scale considerations: [volume of content to review]
- Deployment environment: [cloud service, on-premise, etc.]
- Compliance requirements: [GDPR, CCPA, industry standards, etc.]

Follow these content review best practices:
- Implement multi-layered content filtering approaches
- Use both automated and human review stages
- Apply comprehensive classification taxonomies
- Implement content provenance tracking
- Establish clear escalation pathways for edge cases
- Document review decisions and rationales
- Create feedback loops to improve detection systems
- Consider adversarial testing of content filters
- Apply the principle of least privilege for reviewer access
- Maintain comprehensive audit logs
```

## Security Considerations for Content Training Review

### Content Classification and Filtering

- **Multi-Category Taxonomies**: Implement detailed classification categories for potentially harmful content
- **Filter Strength Levels**: Configure filter sensitivity appropriate to context and use case
- **False Positive Management**: Build mechanisms to handle misclassified benign content
- **Custom Classifiers**: Develop domain-specific classifiers for unique content concerns
- **Classification Confidence**: Track confidence scores to prioritize human review

### Harmful Content Detection

- **Pattern Recognition**: Implement pattern matching for known harmful content
- **Semantic Analysis**: Apply NLP to understand context and intent
- **Embeddings Comparison**: Use vector embeddings to detect similar-to-harmful content
- **Multi-Modal Analysis**: Analyze text and images in context with each other
- **Evolving Detection**: Continuously update detection capabilities for new threats

### Privacy Protection

- **PII Detection**: Implement robust detection for personal identifiable information
- **Data Minimization**: Apply redaction or anonymization techniques
- **Differential Privacy**: Consider differential privacy techniques for aggregate data
- **Access Controls**: Limit reviewer access to sensitive content
- **Data Retention**: Implement appropriate retention policies for reviewed content

### Bias Identification

- **Representation Analysis**: Detect under/over-representation of demographic groups
- **Sentiment Bias**: Identify skewed sentiment associated with specific topics or groups
- **Stereotype Detection**: Recognize and flag stereotypical content patterns
- **Intersectional Analysis**: Consider multiple dimensions of bias simultaneously
- **Mitigation Strategies**: Implement counterbalancing and dataset diversification

## Example Implementation: Text Content Review System

### Content Classification Pipeline

```python
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import logging
import hashlib
import datetime

# Set up secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("content_review.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("content_review")

class ContentReviewPipeline:
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.review_history = []
        
        # Initialize content classifiers
        self._init_classifiers()
        
        # Initialize PII detector
        self._init_pii_detector()
        
        # Set up audit trail
        self.audit_logger = logging.getLogger("content_audit")
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler("content_audit.log")
        audit_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.audit_logger.addHandler(audit_handler)
        
    def _init_classifiers(self):
        # Load pre-trained harmful content classifier
        model_name = self.config["toxicity_model"]
        try:
            self.models["toxicity"] = {
                "tokenizer": AutoTokenizer.from_pretrained(model_name),
                "model": AutoModelForSequenceClassification.from_pretrained(model_name)
            }
            logger.info(f"Loaded toxicity model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to load toxicity model: {str(e)}")
            raise
            
        # Load bias detection model
        bias_model_name = self.config["bias_model"]
        try:
            self.models["bias"] = {
                "tokenizer": AutoTokenizer.from_pretrained(bias_model_name),
                "model": AutoModelForSequenceClassification.from_pretrained(bias_model_name)
            }
            logger.info(f"Loaded bias model: {bias_model_name}")
        except Exception as e:
            logger.error(f"Failed to load bias model: {str(e)}")
            raise
    
    def _init_pii_detector(self):
        # PII detection patterns (simplified example)
        self.pii_patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b',
            "ssn": r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
            "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b'
        }
        
        # Load NER model for PII detection if specified
        if "ner_model" in self.config:
            try:
                from transformers import AutoTokenizer, AutoModelForTokenClassification
                ner_model_name = self.config["ner_model"]
                self.models["ner"] = {
                    "tokenizer": AutoTokenizer.from_pretrained(ner_model_name),
                    "model": AutoModelForTokenClassification.from_pretrained(ner_model_name)
                }
                logger.info(f"Loaded NER model: {ner_model_name}")
            except Exception as e:
                logger.error(f"Failed to load NER model: {str(e)}")
                raise
    
    def review_content(self, content, metadata=None):
        """
        Review content for safety issues
        
        Args:
            content (str): Text content to review
            metadata (dict): Additional context about the content
            
        Returns:
            dict: Review results with safety scores and flags
        """
        content_id = self._generate_content_id(content)
        
        try:
            # Start tracking review process
            review_start = datetime.datetime.now()
            
            # Get basic content stats
            stats = self._get_content_stats(content)
            
            # Check for harmful content
            toxicity_scores = self._check_toxicity(content)
            
            # Check for PII
            pii_findings = self._check_pii(content)
            
            # Check for bias indicators
            bias_scores = self._check_bias(content)
            
            # Determine final decision
            decision = self._make_decision(toxicity_scores, pii_findings, bias_scores)
            
            # Log the review
            self._log_review(content_id, decision, metadata)
            
            # Calculate review time
            review_time = (datetime.datetime.now() - review_start).total_seconds()
            
            # Prepare detailed result
            result = {
                "content_id": content_id,
                "decision": decision["verdict"],
                "confidence": decision["confidence"],
                "review_time_seconds": review_time,
                "flags": {
                    "toxicity": toxicity_scores,
                    "pii": pii_findings,
                    "bias": bias_scores
                },
                "stats": stats
            }
            
            # Add to review history
            self._add_to_history(content_id, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error reviewing content {content_id}: {str(e)}")
            # In case of error, flag for human review
            return {
                "content_id": content_id,
                "decision": "needs_human_review",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def _generate_content_id(self, content):
        """Generate unique ID for content while protecting privacy"""
        # Use hash to avoid storing raw content unnecessarily
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _get_content_stats(self, content):
        """Get basic statistics about content"""
        return {
            "length": len(content),
            "word_count": len(content.split()),
            "language": self._detect_language(content)
        }
    
    def _detect_language(self, text):
        """Detect content language"""
        # Simplified language detection
        # In production, use a proper language detection library
        return "en"  # Default to English
    
    def _check_toxicity(self, content):
        """Check content for toxicity indicators"""
        tokenizer = self.models["toxicity"]["tokenizer"]
        model = self.models["toxicity"]["model"]
        
        # Truncate content if it's too long
        max_length = tokenizer.model_max_length
        encoded = tokenizer(content, truncation=True, max_length=max_length, return_tensors="pt")
        
        with torch.no_grad():
            outputs = model(**encoded)
            scores = torch.softmax(outputs.logits, dim=1).tolist()[0]
        
        # Map scores to toxicity categories
        # This assumes the model outputs scores in a specific order
        categories = ["hate", "harassment", "self_harm", "sexual", "violence"]
        toxicity_scores = {categories[i]: scores[i] for i in range(len(categories))}
        
        return toxicity_scores
    
    def _check_pii(self, content):
        """Check content for personally identifiable information"""
        import re
        
        findings = {}
        
        # Check for PII using regex patterns
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Don't store the actual PII in logs, just count
                findings[pii_type] = len(matches)
        
        # If NER model is available, use it for additional PII detection
        if "ner" in self.models:
            ner_findings = self._check_pii_with_ner(content)
            findings.update(ner_findings)
            
        return findings
    
    def _check_pii_with_ner(self, content):
        """Use NER model to detect PII entities"""
        tokenizer = self.models["ner"]["tokenizer"]
        model = self.models["ner"]["model"]
        
        # Process with NER model
        encoded = tokenizer(content, truncation=True, return_tensors="pt")
        with torch.no_grad():
            outputs = model(**encoded)
        
        # Process outputs to extract entity counts
        # This is a simplified implementation
        ner_findings = {
            "person_names": 2,  # Example placeholder
            "locations": 1      # Example placeholder
        }
        
        return ner_findings
    
    def _check_bias(self, content):
        """Check content for bias indicators"""
        tokenizer = self.models["bias"]["tokenizer"]
        model = self.models["bias"]["model"]
        
        # Truncate content if it's too long
        max_length = tokenizer.model_max_length
        encoded = tokenizer(content, truncation=True, max_length=max_length, return_tensors="pt")
        
        with torch.no_grad():
            outputs = model(**encoded)
            scores = torch.softmax(outputs.logits, dim=1).tolist()[0]
        
        # Map scores to bias categories
        # This assumes the model outputs scores in a specific order
        categories = ["gender", "race", "religion", "age", "disability", "socioeconomic"]
        bias_scores = {categories[i]: scores[i] for i in range(len(categories))}
        
        return bias_scores
    
    def _make_decision(self, toxicity_scores, pii_findings, bias_scores):
        """Make final decision based on all checks"""
        # Check if any toxicity score exceeds threshold
        max_toxicity = max(toxicity_scores.values())
        max_bias = max(bias_scores.values())
        has_pii = sum(pii_findings.values()) > 0
        
        # Decision logic
        if max_toxicity > self.config["thresholds"]["toxicity_high"]:
            return {"verdict": "reject", "confidence": max_toxicity, "reason": "high_toxicity"}
        elif has_pii:
            return {"verdict": "needs_human_review", "confidence": 0.9, "reason": "contains_pii"}
        elif max_toxicity > self.config["thresholds"]["toxicity_medium"]:
            return {"verdict": "needs_human_review", "confidence": max_toxicity, "reason": "medium_toxicity"}
        elif max_bias > self.config["thresholds"]["bias_high"]:
            return {"verdict": "needs_human_review", "confidence": max_bias, "reason": "potential_bias"}
        else:
            confidence = 1.0 - max(max_toxicity, max_bias)
            return {"verdict": "approve", "confidence": confidence, "reason": "passed_all_checks"}
    
    def _log_review(self, content_id, decision, metadata):
        """Log the content review securely"""
        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "content_id": content_id,
            "decision": decision["verdict"],
            "confidence": decision["confidence"],
            "reason": decision["reason"]
        }
        
        # Include metadata if available, but sanitize it first
        if metadata:
            safe_metadata = self._sanitize_metadata(metadata)
            log_data["metadata"] = safe_metadata
            
        # Write to audit log
        self.audit_logger.info(f"Content review: {log_data}")
    
    def _sanitize_metadata(self, metadata):
        """Remove any sensitive information from metadata"""
        # Create a copy to avoid modifying the original
        safe_metadata = metadata.copy()
        
        # Remove any potentially sensitive fields
        sensitive_fields = ["user_id", "email", "ip_address", "session_id"]
        for field in sensitive_fields:
            if field in safe_metadata:
                safe_metadata[field] = f"REDACTED_{field}"
                
        return safe_metadata
    
    def _add_to_history(self, content_id, result):
        """Add review result to history for tracking"""
        # Only keep essential information for history
        history_entry = {
            "content_id": content_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "decision": result["decision"],
            "flags": [k for k, v in result["flags"]["toxicity"].items() if v > 0.5]
        }
        
        # Add to history queue, maintain max size
        self.review_history.append(history_entry)
        if len(self.review_history) > self.config["max_history_size"]:
            self.review_history.pop(0)
            
    def get_review_statistics(self):
        """Get statistics about recent content reviews"""
        if not self.review_history:
            return {"total": 0}
            
        total = len(self.review_history)
        decisions = {}
        for entry in self.review_history:
            decision = entry["decision"]
            decisions[decision] = decisions.get(decision, 0) + 1
            
        # Calculate percentages
        stats = {
            "total": total,
            "decisions": {k: {"count": v, "percentage": (v/total)*100} 
                         for k, v in decisions.items()}
        }
        
        return stats
```

### Human Review Interface (React Component)

```jsx
import React, { useState, useEffect } from 'react';
import { Box, Button, Card, Container, Typography, Chip, LinearProgress,
         Dialog, TextField, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import { DataGrid } from '@mui/x-data-grid';
import axios from 'axios';

// Content Review Component
const ContentReviewInterface = () => {
  const [contents, setContents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedContent, setSelectedContent] = useState(null);
  const [reviewDialogOpen, setReviewDialogOpen] = useState(false);
  const [reviewDecision, setReviewDecision] = useState('');
  const [reviewNotes, setReviewNotes] = useState('');
  const [reviewCategories, setReviewCategories] = useState([]);
  
  // Fetch content that needs human review
  useEffect(() => {
    const fetchContentForReview = async () => {
      try {
        setLoading(true);
        // Secure API call with proper authentication
        const response = await axios.get('/api/content-review/queue', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
          }
        });
        setContents(response.data.contents);
      } catch (error) {
        console.error('Error fetching content for review:', error);
        // Implement proper error handling
      } finally {
        setLoading(false);
      }
    };
    
    fetchContentForReview();
    // Set up polling interval - refresh every 5 minutes
    const intervalId = setInterval(fetchContentForReview, 5 * 60 * 1000);
    
    return () => clearInterval(intervalId);
  }, []);
  
  // Handle content selection for review
  const handleContentSelect = (contentId) => {
    const content = contents.find(c => c.id === contentId);
    setSelectedContent(content);
    setReviewDialogOpen(true);
    
    // Reset review form
    setReviewDecision('');
    setReviewNotes('');
    setReviewCategories([]);
  };
  
  // Submit human review decision
  const handleReviewSubmit = async () => {
    if (!reviewDecision) {
      alert('Please select a decision');
      return;
    }
    
    try {
      // Log start of review submission for audit trail
      console.log(`Submitting review for content ${selectedContent.id}`);
      
      // Send review decision to API with proper authentication
      await axios.post(`/api/content-review/decisions`, {
        contentId: selectedContent.id,
        decision: reviewDecision,
        categories: reviewCategories,
        notes: reviewNotes,
        reviewerId: getCurrentUserId() // Get from auth context
      }, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
          'X-CSRF-Token': getCSRFToken() // CSRF protection
        }
      });
      
      // Update local state to remove reviewed content
      setContents(contents.filter(c => c.id !== selectedContent.id));
      
      // Close dialog
      setReviewDialogOpen(false);
      setSelectedContent(null);
      
    } catch (error) {
      console.error('Error submitting content review:', error);
      // Implement proper error handling and retry mechanism
    }
  };
  
  // Format flags for display
  const formatFlags = (flags) => {
    return Object.entries(flags).map(([key, value]) => (
      <Chip 
        key={key} 
        label={`${key}: ${(value * 100).toFixed(1)}%`} 
        color={value > 0.7 ? "error" : value > 0.4 ? "warning" : "default"}
        style={{ margin: '2px' }}
      />
    ));
  };
  
  // Data grid columns
  const columns = [
    { field: 'id', headerName: 'ID', width: 90 },
    { field: 'snippet', headerName: 'Content Snippet', width: 300 },
    { 
      field: 'flags', 
      headerName: 'Flags', 
      width: 300,
      renderCell: (params) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap' }}>
          {formatFlags(params.value)}
        </Box>
      )
    },
    { 
      field: 'confidence', 
      headerName: 'AI Confidence', 
      width: 150,
      renderCell: (params) => (
        <LinearProgress 
          variant="determinate" 
          value={params.value * 100} 
          color={params.value < 0.4 ? "error" : params.value < 0.7 ? "warning" : "success"}
          sx={{ width: '80%', height: 10 }}
        />
      )
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      renderCell: (params) => (
        <Button 
          variant="contained" 
          size="small" 
          onClick={() => handleContentSelect(params.row.id)}
        >
          Review
        </Button>
      ),
    },
  ];

  return (
    <Container maxWidth="xl">
      <Typography variant="h4" gutterBottom>
        Content Review Queue
      </Typography>
      <Typography variant="subtitle1" gutterBottom>
        {contents.length} items pending human review
      </Typography>
      
      {loading ? (
        <LinearProgress />
      ) : (
        <div style={{ height: 600, width: '100%' }}>
          <DataGrid
            rows={contents}
            columns={columns}
            pageSize={10}
            rowsPerPageOptions={[10, 25, 50]}
            checkboxSelection
            disableSelectionOnClick
            loading={loading}
          />
        </div>
      )}
      
      {/* Review Dialog */}
      <Dialog 
        open={reviewDialogOpen} 
        onClose={() => setReviewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedContent && (
          <Box sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Review Content
            </Typography>
            
            <Card variant="outlined" sx={{ p: 2, mb: 3, bgcolor: 'grey.50' }}>
              <Typography variant="body1">
                {selectedContent.fullContent}
              </Typography>
            </Card>
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2">AI Detected Issues:</Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', mt: 1 }}>
                {formatFlags(selectedContent.flags)}
              </Box>
            </Box>
            
            <FormControl fullWidth margin="normal">
              <InputLabel>Decision</InputLabel>
              <Select
                value={reviewDecision}
                onChange={(e) => setReviewDecision(e.target.value)}
                required
              >
                <MenuItem value="approve">Approve</MenuItem>
                <MenuItem value="reject">Reject</MenuItem>
                <MenuItem value="modify">Approve with Modifications</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl fullWidth margin="normal">
              <InputLabel>Flag Categories</InputLabel>
              <Select
                multiple
                value={reviewCategories}
                onChange={(e) => setReviewCategories(e.target.value)}
                renderValue={(selected) => (
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selected.map((value) => (
                      <Chip key={value} label={value} />
                    ))}
                  </Box>
                )}
              >
                <MenuItem value="hate_speech">Hate Speech</MenuItem>
                <MenuItem value="harassment">Harassment</MenuItem>
                <MenuItem value="violence">Violence</MenuItem>
                <MenuItem value="sexual_content">Sexual Content</MenuItem>
                <MenuItem value="self_harm">Self-harm</MenuItem>
                <MenuItem value="misinformation">Misinformation</MenuItem>
                <MenuItem value="bias">Bias</MenuItem>
                <MenuItem value="pii">Personal Information</MenuItem>
              </Select>
            </FormControl>
            
            <TextField
              label="Review Notes"
              multiline
              rows={4}
              fullWidth
              margin="normal"
              value={reviewNotes}
              onChange={(e) => setReviewNotes(e.target.value)}
            />
            
            <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
              <Button 
                onClick={() => setReviewDialogOpen(false)} 
                sx={{ mr: 1 }}
              >
                Cancel
              </Button>
              <Button 
                variant="contained" 
                onClick={handleReviewSubmit}
                color="primary"
              >
                Submit Review
              </Button>
            </Box>
          </Box>
        )}
      </Dialog>
    </Container>
  );
};

// Helper functions
const getCurrentUserId = () => {
  // Get from authentication context in a real app
  return 'reviewer-123';
};

const getCSRFToken = () => {
  // Get CSRF token from meta tag or cookie in a real app
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
};

export default ContentReviewInterface;
```

## Security Testing for Content Review Systems

### Automated Testing

- **Unit Tests**: Validate classification accuracy and boundary conditions
- **Integration Tests**: Verify end-to-end content review pipeline
- **Adversarial Testing**: Attempt to bypass content filters with evasion techniques
- **Performance Testing**: Verify system under high-volume conditions

### Common Vulnerabilities to Test

- **Filter Bypasses**: Test for content that evades detection
- **False Positives/Negatives**: Evaluate classification accuracy
- **Processing Exploits**: Check for DoS via complex content
- **Data Leakage**: Ensure PII is properly handled
- **Access Control**: Verify reviewer permissions are properly enforced

## References

- OWASP AI Security and Privacy Guide: https://owasp.org/www-project-ai-security-and-privacy-guide/
- Google's Responsible AI Practices: https://ai.google/responsibilities/responsible-ai-practices/
- AI Incident Database: https://incidentdatabase.ai/
- ISO/IEC 42001: AI Management System Standard
