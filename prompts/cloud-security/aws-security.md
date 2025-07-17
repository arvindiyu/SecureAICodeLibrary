# AWS Security Configuration Guidelines

## Prompt

As an AWS Security Configuration Specialist, help me implement secure cloud infrastructure on AWS. I need guidance on securing my AWS resources using best practices for Identity and Access Management (IAM), network security, encryption, monitoring, and compliance.

### Identity & Access Management (IAM)
- Implement principle of least privilege for all IAM roles and policies
- Use IAM roles instead of long-term access keys
- Enable MFA for all users, especially privileged accounts
- Implement proper IAM policies with specific resource-level permissions
- Regularly audit and rotate credentials

### Network Security
- Implement proper VPC design with public and private subnets
- Use security groups as the first line of defense
- Implement network ACLs for additional security
- Use AWS PrivateLink for private connectivity
- Enable VPC Flow Logs for network monitoring

### Data Protection & Encryption
- Encrypt data at rest using KMS or AWS managed keys
- Implement encryption in transit using TLS/SSL
- Use AWS Secrets Manager for secure storage of secrets
- Implement proper S3 bucket policies and block public access
- Enable encryption for EBS volumes, RDS instances, and S3 buckets

### Monitoring & Detection
- Enable AWS CloudTrail across all regions
- Configure Amazon GuardDuty for threat detection
- Set up AWS Config for resource compliance
- Implement Amazon CloudWatch alarms for suspicious activities
- Use AWS Security Hub for security posture management

### Compliance & Governance
- Implement AWS Organizations for multi-account strategy
- Use Service Control Policies (SCPs) to enforce security guardrails
- Implement AWS Config Rules for compliance monitoring
- Use AWS Audit Manager for compliance reporting
- Implement tagging strategy for resource governance

## Example AWS CloudFormation Template with Security Best Practices

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Secure AWS Infrastructure Example'

Resources:
  # Secure VPC Configuration
  SecureVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: SecureVPC

  # Private Subnet
  PrivateSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref SecureVPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: PrivateSubnet

  # Public Subnet
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref SecureVPC
      CidrBlock: 10.0.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: PublicSubnet

  # Internet Gateway
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: SecureIGW

  # Attach Gateway to VPC
  GatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref SecureVPC
      InternetGatewayId: !Ref InternetGateway

  # Route Tables
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref SecureVPC
      Tags:
        - Key: Name
          Value: PublicRouteTable

  PrivateRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref SecureVPC
      Tags:
        - Key: Name
          Value: PrivateRouteTable

  # Routes
  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: GatewayAttachment
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway

  # Subnet Associations
  PublicSubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref PublicRouteTable

  PrivateSubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PrivateSubnet
      RouteTableId: !Ref PrivateRouteTable

  # Secure Security Group
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for web servers
      VpcId: !Ref SecureVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
          Description: HTTPS from internet
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
          Description: Allow HTTPS outbound

  # Encrypted S3 Bucket with Private Access
  SecureDataBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled
      LoggingConfiguration:
        DestinationBucketName: !Ref LogBucket
        LogFilePrefix: s3-access-logs/

  # Bucket Policy to Enforce HTTPS
  SecureBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref SecureDataBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: EnforceHTTPS
            Effect: Deny
            Principal: '*'
            Action: 's3:*'
            Resource:
              - !Sub 'arn:aws:s3:::${SecureDataBucket}/*'
              - !Sub 'arn:aws:s3:::${SecureDataBucket}'
            Condition:
              Bool:
                'aws:SecureTransport': false

  # Log Bucket for Access Logs
  LogBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      AccessControl: LogDeliveryWrite
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

  # Enable CloudTrail
  CloudTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      S3BucketName: !Ref CloudTrailBucket
      EnableLogFileValidation: true
      IncludeGlobalServiceEvents: true
      IsMultiRegionTrail: true
      CloudWatchLogsLogGroupArn: !GetAtt CloudTrailLogGroup.Arn
      CloudWatchLogsRoleArn: !GetAtt CloudTrailRole.Arn

  # CloudTrail S3 Bucket
  CloudTrailBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      VersioningConfiguration:
        Status: Enabled
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

  # CloudTrail Bucket Policy
  CloudTrailBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref CloudTrailBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AWSCloudTrailAclCheck
            Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: s3:GetBucketAcl
            Resource: !Sub 'arn:aws:s3:::${CloudTrailBucket}'
          - Sid: AWSCloudTrailWrite
            Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: s3:PutObject
            Resource: !Sub 'arn:aws:s3:::${CloudTrailBucket}/AWSLogs/${AWS::AccountId}/*'
            Condition:
              StringEquals:
                s3:x-amz-acl: bucket-owner-full-control

  # CloudTrail Log Group
  CloudTrailLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: 90

  # IAM Role for CloudTrail
  CloudTrailRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudtrail.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/CloudWatchLogsFullAccess

  # GuardDuty Detector
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

Outputs:
  VpcId:
    Description: VPC ID
    Value: !Ref SecureVPC
  PrivateSubnet:
    Description: Private Subnet
    Value: !Ref PrivateSubnet
  PublicSubnet:
    Description: Public Subnet
    Value: !Ref PublicSubnet
  SecureDataBucketName:
    Description: Secure S3 Bucket Name
    Value: !Ref SecureDataBucket
```

## AWS Security Best Practices Checklist

### Identity & Access Management
- [ ] Use IAM roles for EC2 instances instead of access keys
- [ ] Enable MFA for all IAM users
- [ ] Implement a password policy with minimum complexity
- [ ] Rotate access keys regularly
- [ ] Review IAM permissions regularly and remove unnecessary privileges
- [ ] Use IAM Access Analyzer to identify unintended access

### Network Security
- [ ] Implement security groups with minimum required access
- [ ] Use network ACLs as an additional layer of security
- [ ] Implement VPC endpoints for AWS services
- [ ] Enable VPC Flow Logs for network monitoring
- [ ] Use AWS WAF for web application protection
- [ ] Implement AWS Shield for DDoS protection

### Data Protection
- [ ] Encrypt EBS volumes
- [ ] Enable S3 bucket encryption
- [ ] Use KMS for key management
- [ ] Enable RDS encryption
- [ ] Block public access to S3 buckets
- [ ] Implement S3 bucket versioning

### Monitoring & Logging
- [ ] Enable CloudTrail across all regions
- [ ] Configure CloudWatch alarms for suspicious activities
- [ ] Enable GuardDuty for threat detection
- [ ] Use AWS Config for compliance monitoring
- [ ] Implement centralized logging
- [ ] Set up SNS notifications for critical events

### Compliance & Governance
- [ ] Implement AWS Organizations with SCPs
- [ ] Use AWS Config Rules for compliance checks
- [ ] Implement resource tagging strategy
- [ ] Use AWS Trusted Advisor for best practice checks
- [ ] Implement regular security assessments
- [ ] Document security policies and procedures

## Additional AWS Security Resources

1. [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
2. [AWS Security Documentation](https://docs.aws.amazon.com/security/)
3. [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
4. [AWS Security Hub Documentation](https://docs.aws.amazon.com/securityhub/)
