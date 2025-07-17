# Terraform Security Best Practices

## Prompt

As a Terraform Security Specialist, help me implement secure Infrastructure as Code (IaC) practices. I need guidance on writing secure Terraform configurations, managing state securely, implementing proper access controls, and following security best practices for infrastructure provisioning.

### Secure Terraform Configuration
- Implement resource-level security controls
- Use modules for consistent security implementation
- Implement proper input validation
- Use security-focused providers and modules
- Implement secure defaults
- Use variables for sensitive configuration

### State Management & Secrets
- Use remote backend with encryption
- Avoid storing secrets in state files
- Implement state locking
- Use dynamic secrets from vault systems
- Configure proper backend access controls
- Implement proper state backup strategies

### Access Control & Authentication
- Implement least privilege for Terraform execution
- Use temporary credentials where possible
- Implement proper CI/CD pipeline security
- Secure API tokens and credentials
- Implement proper authentication for providers
- Use separate credentials for different environments

### Infrastructure Security
- Implement network security controls (security groups, NACLs)
- Enable encryption for data at rest and in transit
- Implement proper IAM policies and roles
- Enable logging and monitoring
- Implement compliance as code
- Use security groups with minimal access

### Testing & Validation
- Implement security scanning for Terraform code
- Use terraform validate and fmt in pipelines
- Implement policy as code (Sentinel, OPA)
- Test security controls before deployment
- Implement automated compliance checking
- Use infrastructure testing frameworks

## Example Terraform Configuration with Security Best Practices

```hcl
# Configure the AWS Provider with minimal permissions
provider "aws" {
  region = "us-west-2"
  
  # Explicitly define which version of the provider to use
  version = "~> 3.0"
  
  # Better to use environment variables or assumed roles than hardcoded credentials
  # Use AssumeRole for cross-account access
  assume_role {
    role_arn = "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"
  }
}

# Configure remote backend with encryption and locking
terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "secure-infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    
    # Better to specify this through environment variables
    # role_arn       = "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"
  }
  
  # Lock provider versions
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Use variables for configuration with constraints
variable "environment" {
  description = "Environment (dev, test, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "Environment must be one of: dev, test, prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

# Secure VPC implementation
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.0.0"  # Lock module version
  
  name = "secure-vpc-${var.environment}"
  cidr = var.vpc_cidr
  
  azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  # Security features
  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "prod"  # HA NAT for prod
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true
  
  # VPC Flow Logs for network monitoring
  enable_flow_log                      = true
  flow_log_destination_type            = "s3"
  flow_log_destination_arn             = aws_s3_bucket.flow_logs.arn
  flow_log_traffic_type                = "ALL"
  flow_log_max_aggregation_interval    = 60
  
  # Default security group with no ingress/egress
  manage_default_security_group  = true
  default_security_group_ingress = []
  default_security_group_egress  = []
  
  # Tags for resource tracking
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "Security"
  }
}

# S3 bucket for VPC flow logs with encryption and access controls
resource "aws_s3_bucket" "flow_logs" {
  bucket = "vpc-flow-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  acl    = "private"
  
  # Enable server-side encryption
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Enable versioning
  versioning {
    enabled = true
  }
  
  # Lifecycle rules
  lifecycle_rule {
    id      = "log"
    enabled = true
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
  
  tags = {
    Name        = "vpc-flow-logs-${var.environment}"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Bucket policy to enforce encryption and secure access
resource "aws_s3_bucket_policy" "flow_logs_policy" {
  bucket = aws_s3_bucket.flow_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.flow_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "AWSLogDeliveryCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.flow_logs.arn
      },
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.flow_logs.arn,
          "${aws_s3_bucket.flow_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Secure security group implementation
resource "aws_security_group" "web_sg" {
  name        = "web-${var.environment}-sg"
  description = "Security group for web servers"
  vpc_id      = module.vpc.vpc_id
  
  # Minimal ingress rules
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }
  
  # Explicit egress rules (default deny all)
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to internet"
  }
  
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP to internet"
  }
  
  # Tag security groups
  tags = {
    Name        = "web-${var.environment}-sg"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
  
  # Ensure description for all rules
  lifecycle {
    precondition {
      condition     = length(var.environment) > 0
      error_message = "Environment variable must be set."
    }
  }
}

# Use KMS for encryption
resource "aws_kms_key" "app_key" {
  description             = "KMS key for application encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  # Key policy with least privilege
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Database with encryption and security controls
resource "aws_db_instance" "app_db" {
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "postgres"
  engine_version         = "13.4"
  instance_class         = "db.t3.micro"
  name                   = "appdb"
  username               = "dbadmin"
  password               = var.db_password  # Use secrets management!
  parameter_group_name   = "default.postgres13"
  skip_final_snapshot    = var.environment != "prod"  # Always snapshot in prod
  
  # Security features
  storage_encrypted          = true
  kms_key_id                 = aws_kms_key.app_key.arn
  multi_az                   = var.environment == "prod"
  backup_retention_period    = var.environment == "prod" ? 30 : 7
  deletion_protection        = var.environment == "prod"
  publicly_accessible        = false
  vpc_security_group_ids     = [aws_security_group.db_sg.id]
  db_subnet_group_name       = aws_db_subnet_group.app_db.name
  
  # Enable monitoring
  monitoring_interval        = 60
  monitoring_role_arn        = aws_iam_role.rds_monitoring_role.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Subnet group for database
resource "aws_db_subnet_group" "app_db" {
  name       = "app-db-subnet-group"
  subnet_ids = module.vpc.private_subnets
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Security group for database with minimal access
resource "aws_security_group" "db_sg" {
  name        = "db-${var.environment}-sg"
  description = "Security group for database"
  vpc_id      = module.vpc.vpc_id
  
  # Only allow connections from web tier
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
    description     = "PostgreSQL from web tier"
  }
  
  # No outbound connections needed for database
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name        = "db-${var.environment}-sg"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# IAM role for RDS monitoring
resource "aws_iam_role" "rds_monitoring_role" {
  name = "rds-monitoring-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
  
  # Attach the AWS managed policy
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"]
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Get current account ID for resource naming
data "aws_caller_identity" "current" {}

# Output important information
output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnet_ids" {
  value = module.vpc.private_subnets
}

output "public_subnet_ids" {
  value = module.vpc.public_subnets
}

# Don't output sensitive information
output "db_instance_endpoint" {
  value = aws_db_instance.app_db.endpoint
  sensitive = true
}

output "kms_key_id" {
  value = aws_kms_key.app_key.key_id
}

output "flow_logs_bucket" {
  value = aws_s3_bucket.flow_logs.bucket
}
```

## Terraform Security Checklist

### Configuration & State Management
- [ ] Use remote backend with encryption
- [ ] Implement state locking
- [ ] Avoid storing secrets in state files
- [ ] Use version constraints for providers and modules
- [ ] Use input validation for variables
- [ ] Store terraform.tfstate files securely
- [ ] Use .gitignore to prevent committing sensitive files

### Authentication & Access Control
- [ ] Use temporary credentials or assumed roles
- [ ] Implement least privilege for Terraform IAM roles
- [ ] Secure API tokens and credentials
- [ ] Use different credentials per environment
- [ ] Implement proper backend access controls
- [ ] Use secure methods for providing credentials

### Module & Provider Security
- [ ] Pin module versions
- [ ] Use official or trusted modules
- [ ] Audit third-party modules for security
- [ ] Pin provider versions
- [ ] Use security-focused modules
- [ ] Implement consistent security controls across modules

### Resource Security
- [ ] Encrypt data at rest
- [ ] Encrypt data in transit
- [ ] Implement proper IAM policies and roles
- [ ] Secure network configurations (security groups, NACLs)
- [ ] Enable logging and monitoring
- [ ] Implement proper access controls for resources

### Testing & Validation
- [ ] Use terraform validate in CI/CD pipelines
- [ ] Implement automated security scanning
- [ ] Use policy as code (Sentinel, OPA)
- [ ] Test security controls before deployment
- [ ] Use static code analysis tools
- [ ] Implement compliance as code

## Additional Terraform Security Resources

1. [HashiCorp Terraform Security Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
2. [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
3. [Terraform Security Modules](https://registry.terraform.io/browse/modules?provider=aws&category=security)
4. [Terraform Testing Framework](https://www.terraform.io/docs/language/modules/testing-experiment.html)
5. [Checkov - Terraform Security Scanner](https://www.checkov.io/)
