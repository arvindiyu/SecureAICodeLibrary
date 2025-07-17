# Google Cloud Platform (GCP) Security Configuration Guidelines

## Prompt

As a GCP Security Configuration Specialist, help me implement secure cloud infrastructure on Google Cloud Platform. I need guidance on securing GCP resources using best practices for Identity and Access Management (IAM), network security, encryption, monitoring, and compliance.

### Identity & Access Management (IAM)
- Implement principle of least privilege with IAM roles
- Use service accounts with minimum required permissions
- Implement organization-level IAM policies
- Enable Cloud Identity for centralized user management
- Use IAM Conditions for fine-grained access control
- Implement VPC Service Controls to restrict data access

### Network Security
- Design secure VPC networks with proper segmentation
- Implement firewalls and security rules
- Use Private Google Access for services
- Implement Cloud NAT for secure outbound connectivity
- Enable VPC Flow Logs for network monitoring
- Use Cloud Armor for DDoS protection

### Data Protection & Encryption
- Enable default encryption for Cloud Storage
- Use Customer-Managed Encryption Keys (CMEK) for sensitive data
- Implement Secret Manager for sensitive information
- Enable encryption for Compute Engine disks
- Implement Data Loss Prevention (DLP) API for sensitive data
- Enable Cloud KMS for key management

### Monitoring & Detection
- Enable Cloud Audit Logs for all services
- Implement Cloud Security Command Center
- Configure security alerts and notifications
- Use Cloud Monitoring for resource monitoring
- Implement log-based metrics for security events
- Enable Access Transparency logs

### Compliance & Governance
- Implement Organization Policy Service
- Use Forseti Security for compliance monitoring
- Implement resource hierarchy with folders and projects
- Use labels and tags for resource governance
- Implement regular compliance assessments
- Use Security Health Analytics

## Example Terraform Configuration with Security Best Practices

```hcl
# Provider configuration
provider "google" {
  project = "secure-gcp-project"
  region  = "us-central1"
}

# Create VPC network with private subnets
resource "google_compute_network" "secure_vpc" {
  name                    = "secure-vpc"
  auto_create_subnetworks = false
}

# Create private subnet
resource "google_compute_subnetwork" "private_subnet" {
  name          = "private-subnet"
  ip_cidr_range = "10.0.1.0/24"
  network       = google_compute_network.secure_vpc.id
  region        = "us-central1"
  
  # Enable flow logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  # Enable private Google access
  private_ip_google_access = true
}

# Create firewall rule to allow internal communication
resource "google_compute_firewall" "internal_traffic" {
  name    = "allow-internal"
  network = google_compute_network.secure_vpc.id
  
  allow {
    protocol = "tcp"
  }
  
  allow {
    protocol = "udp"
  }
  
  allow {
    protocol = "icmp"
  }
  
  source_ranges = ["10.0.1.0/24"]
}

# Create firewall rule to allow specific external traffic
resource "google_compute_firewall" "allow_https" {
  name    = "allow-https"
  network = google_compute_network.secure_vpc.id
  
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["https-server"]
}

# Create service account with minimal permissions
resource "google_service_account" "app_service_account" {
  account_id   = "app-service-account"
  display_name = "Application Service Account"
}

# Assign role to service account
resource "google_project_iam_member" "app_sa_role" {
  project = "secure-gcp-project"
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.app_service_account.email}"
}

# Create encrypted Cloud Storage bucket
resource "google_storage_bucket" "secure_bucket" {
  name          = "secure-data-bucket"
  location      = "US"
  force_destroy = false
  
  # Enable uniform bucket-level access
  uniform_bucket_level_access = true
  
  # Enable versioning
  versioning {
    enabled = true
  }
  
  # Encryption
  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }
  
  # Lifecycle rules
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

# Deny public access to bucket
resource "google_storage_bucket_iam_binding" "binding" {
  bucket = google_storage_bucket.secure_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "serviceAccount:${google_service_account.app_service_account.email}",
  ]
}

# Create KMS key for bucket encryption
resource "google_kms_key_ring" "key_ring" {
  name     = "secure-key-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "bucket_key" {
  name     = "bucket-encryption-key"
  key_ring = google_kms_key_ring.key_ring.id
  
  # Auto-rotation settings
  rotation_period = "7776000s" # 90 days
  
  # Prevent destruction
  lifecycle {
    prevent_destroy = true
  }
}

# Enable Cloud Security Command Center
resource "google_project_service" "scc_service" {
  project = "secure-gcp-project"
  service = "securitycenter.googleapis.com"
  
  disable_dependent_services = false
}

# Enable Cloud Audit Logging
resource "google_project_iam_audit_config" "audit_config" {
  project = "secure-gcp-project"
  service = "allServices"
  
  audit_log_config {
    log_type = "DATA_READ"
  }
  
  audit_log_config {
    log_type = "DATA_WRITE"
  }
  
  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

# Create a log sink for exporting audit logs
resource "google_logging_project_sink" "audit_log_sink" {
  name        = "audit-log-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  
  filter = "logName:\"projects/secure-gcp-project/logs/cloudaudit.googleapis.com%2Factivity\""
  
  unique_writer_identity = true
}

# Create a bucket for audit logs
resource "google_storage_bucket" "audit_logs" {
  name          = "secure-gcp-project-audit-logs"
  location      = "US"
  force_destroy = false
  
  uniform_bucket_level_access = true
  
  # Enable versioning
  versioning {
    enabled = true
  }
  
  # Lifecycle rules
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

# Allow log sink service account to write to the bucket
resource "google_storage_bucket_iam_binding" "log_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  
  members = [
    google_logging_project_sink.audit_log_sink.writer_identity,
  ]
}

# Create a custom organization policy
resource "google_organization_policy" "require_oslogin" {
  org_id     = "secure-gcp-project"
  constraint = "compute.requireOsLogin"
  
  boolean_policy {
    enforced = true
  }
}

# Enable VPC Service Controls
resource "google_access_context_manager_service_perimeter" "service_perimeter" {
  parent = "accessPolicies/${google_access_context_manager_access_policy.access_policy.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.access_policy.name}/servicePerimeters/secure_perimeter"
  title  = "Secure Service Perimeter"
  
  status {
    resources = ["projects/secure-gcp-project"]
    
    restricted_services = [
      "storage.googleapis.com",
      "bigquery.googleapis.com",
    ]
    
    vpc_accessible_services {
      enable_restriction = true
      allowed_services   = ["storage.googleapis.com"]
    }
  }
}

# Create access policy for VPC Service Controls
resource "google_access_context_manager_access_policy" "access_policy" {
  parent = "organizations/123456789"
  title  = "Secure Access Policy"
}
```

## GCP Security Best Practices Checklist

### Identity & Access Management
- [ ] Use service accounts with minimum required permissions
- [ ] Enable Cloud Identity for user management
- [ ] Implement organization-level IAM policies
- [ ] Use IAM Conditions for time-bound access
- [ ] Implement VPC Service Controls
- [ ] Regularly audit IAM permissions

### Network Security
- [ ] Implement network segmentation with VPCs
- [ ] Configure firewall rules with least privilege
- [ ] Enable Private Google Access
- [ ] Use Cloud NAT for secure outbound traffic
- [ ] Enable VPC Flow Logs
- [ ] Implement Cloud Armor for DDoS protection

### Data Protection
- [ ] Enable default encryption for Cloud Storage
- [ ] Use Customer-Managed Encryption Keys (CMEK)
- [ ] Implement Secret Manager for sensitive information
- [ ] Enable Cloud DLP for sensitive data protection
- [ ] Configure Object Lifecycle Management
- [ ] Implement access controls for data access

### Monitoring & Logging
- [ ] Enable Cloud Audit Logs
- [ ] Configure Security Command Center
- [ ] Set up log exports to secure destinations
- [ ] Implement alerting for security events
- [ ] Enable Access Transparency
- [ ] Configure regular security scans

### Compliance & Governance
- [ ] Implement Organization Policy Service
- [ ] Use resource hierarchy (organization, folders, projects)
- [ ] Implement labeling and tagging strategy
- [ ] Use Forseti Security for compliance monitoring
- [ ] Implement regular compliance assessments
- [ ] Configure Security Health Analytics

## Additional GCP Security Resources

1. [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
2. [GCP Security Documentation](https://cloud.google.com/security)
3. [GCP Security Command Center](https://cloud.google.com/security-command-center)
4. [GCP Compliance Offerings](https://cloud.google.com/security/compliance)
