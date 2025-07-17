# Container Security Best Practices

This guide provides comprehensive security best practices for container technologies including Docker, Kubernetes, and other container orchestration platforms.

## Table of Contents

1. [Container Image Security](#container-image-security)
2. [Runtime Security](#runtime-security)
3. [Orchestration Security](#orchestration-security)
4. [Network Security](#network-security)
5. [Secret Management](#secret-management)
6. [Monitoring and Detection](#monitoring-and-detection)
7. [Compliance and Auditing](#compliance-and-auditing)
8. [Security Tools and Resources](#security-tools-and-resources)

## Container Image Security

### Secure Base Images

1. **Use minimal base images**
   - Alpine Linux, Google's Distroless, or scratch images reduce attack surface
   - Remove unnecessary packages and components

```dockerfile
# INSECURE: Using a full-featured OS as base
FROM ubuntu:latest

# SECURE: Using a minimal base image
FROM alpine:3.18
# OR
FROM gcr.io/distroless/static-debian11
# OR for specific languages
FROM gcr.io/distroless/java17-debian11
```

2. **Pin specific image versions**
   - Never use `latest` tags in production
   - Use digest pinning for immutability

```dockerfile
# INSECURE: Using latest tag
FROM node:latest

# SECURE: Using specific version
FROM node:18.17.1-alpine3.18

# EVEN MORE SECURE: Using digest pinning
FROM node@sha256:b3f9823f0a4b0a2ecb215c3b50ff9df07c1a766f1e59e664317e7f02e3308d81
```

3. **Multi-stage builds**
   - Separate build and runtime environments
   - Reduce final image size and attack surface

```dockerfile
# Build stage
FROM maven:3.9.4-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
USER 10001
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### Image Scanning and Vulnerability Management

1. **Implement automated scanning**
   - Scan for known vulnerabilities (CVEs)
   - Scan for sensitive data and secrets
   - Perform static analysis of container files

2. **Enforce security gates in CI/CD**
   - Block builds with critical vulnerabilities
   - Apply policy-based approvals

```yaml
# Example GitHub Actions workflow with Trivy scanner
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

3. **Image signing and verification**
   - Sign container images with tools like Cosign, Notary
   - Verify signatures before deployment

```bash
# Signing an image with Cosign
cosign sign --key cosign.key myregistry/myapp:1.0.0

# Verifying an image
cosign verify --key cosign.pub myregistry/myapp:1.0.0
```

### Image Hardening Techniques

1. **Run as non-root user**
   - Create custom users with minimal privileges
   - Set user in Dockerfile

```dockerfile
# Create a dedicated user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set ownership
COPY --chown=appuser:appgroup . /app

# Switch to non-root user
USER appuser
```

2. **Set filesystem to read-only**
   - Mount container filesystems as read-only
   - Use tmpfs for writable directories

```yaml
# Kubernetes pod with read-only filesystem
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: myapp:1.0.0
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: tmp-volume
    emptyDir: {}
```

3. **Remove shell access**
   - Use distroless images without shell
   - Remove debugging tools

## Runtime Security

### Container Runtime Protection

1. **Use seccomp profiles**
   - Restrict system calls available to containers
   - Apply default seccomp profiles or create custom ones

```yaml
# Kubernetes pod with seccomp profile
apiVersion: v1
kind: Pod
metadata:
  name: audit-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "runtime/default"
spec:
  containers:
  - name: app
    image: myapp:1.0.0
```

2. **Configure AppArmor/SELinux**
   - Restrict container capabilities with mandatory access control
   - Apply profiles to container runtime

```yaml
# Kubernetes pod with AppArmor profile
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: "runtime/default"
spec:
  containers:
  - name: app
    image: myapp:1.0.0
```

3. **Linux capabilities**
   - Drop all capabilities and add only required ones
   - Follow principle of least privilege

```yaml
# Kubernetes pod with minimal capabilities
apiVersion: v1
kind: Pod
metadata:
  name: secure-capabilities-pod
spec:
  containers:
  - name: app
    image: myapp:1.0.0
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE # Only if needed to bind to ports < 1024
```

### Resource Restrictions

1. **Set resource limits**
   - Prevent resource exhaustion attacks
   - Set CPU, memory limits and requests

```yaml
# Kubernetes pod with resource limits
apiVersion: v1
kind: Pod
metadata:
  name: resource-limited-pod
spec:
  containers:
  - name: app
    image: myapp:1.0.0
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
```

2. **Configure cgroup limits in Docker**
   - Limit memory, CPU, and pids

```bash
# Docker run with resource limits
docker run -d --name mycontainer \
  --memory="128m" \
  --memory-swap="256m" \
  --cpu-shares=1024 \
  --pids-limit=100 \
  myapp:1.0.0
```

## Orchestration Security

### Kubernetes-Specific Security

1. **Use Pod Security Standards**
   - Apply Privileged, Baseline, or Restricted policies
   - Enforce via Pod Security Admission or OPA/Gatekeeper

```yaml
# Kubernetes namespace with Pod Security Standards
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

2. **Role-Based Access Control (RBAC)**
   - Define fine-grained permissions
   - Apply principle of least privilege to service accounts

```yaml
# Kubernetes RBAC configuration
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-service-account
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

3. **Network Policies**
   - Segment network communication between pods
   - Implement zero-trust networking model

```yaml
# Default deny all ingress/egress traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

4. **Control plane security**
   - Secure etcd with encryption and authentication
   - Enable audit logging
   - Use TLS for all API communications

### General Orchestration Security

1. **Admission controllers**
   - Validate and mutate requests to the orchestrator API
   - Enforce security policies

```yaml
# OPA/Gatekeeper constraint template
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          properties:
            labels:
              type: array
              items: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

2. **Secret rotation**
   - Regularly rotate service accounts and secrets
   - Use short-lived credentials

## Network Security

### Container Network Security

1. **Encrypt network traffic**
   - Implement mutual TLS between services
   - Use service meshes like Istio or Linkerd

```yaml
# Istio destination rule with TLS
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: secure-service
spec:
  host: myservice.default.svc.cluster.local
  trafficPolicy:
    tls:
      mode: MUTUAL
      clientCertificate: /etc/certs/cert-chain.pem
      privateKey: /etc/certs/key.pem
      caCertificates: /etc/certs/root-cert.pem
```

2. **Network segmentation**
   - Use network namespaces
   - Implement microsegmentation with CNI plugins

3. **Egress filtering**
   - Control outbound traffic from containers
   - Prevent data exfiltration

## Secret Management

1. **External secret stores**
   - Use Vault, AWS Secrets Manager, or cloud-native solutions
   - Avoid storing secrets in container images or environment variables

```yaml
# Kubernetes pod using external-secrets operator with AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: database-credentials-secret
  data:
  - secretKey: username
    remoteRef:
      key: prod/db-credentials
      property: username
  - secretKey: password
    remoteRef:
      key: prod/db-credentials
      property: password
```

2. **Secret injection**
   - Mount secrets as files instead of environment variables
   - Use secret volume mounts with memory-only file systems

```yaml
# Kubernetes pod with secrets mounted as files
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: myapp:1.0.0
    volumeMounts:
    - name: secrets
      mountPath: "/etc/secrets"
      readOnly: true
  volumes:
  - name: secrets
    secret:
      secretName: app-secrets
```

3. **Secret encryption**
   - Encrypt secrets at rest
   - Use envelope encryption for sensitive data

## Monitoring and Detection

1. **Runtime monitoring**
   - Implement behavioral analysis
   - Use tools like Falco, Sysdig, or cloud-native security solutions

```yaml
# Falco rule for detecting suspicious activities
- rule: Terminal shell in container
  desc: A shell was spawned by a program in a container
  condition: container and shell_procs and not container_entrypoint
  output: Shell spawned in container (user=%user.name container_id=%container.id container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
```

2. **Log analysis**
   - Centralize container logs
   - Implement automated alerting
   - Use SIEM solutions for correlation

3. **Vulnerability management**
   - Continuously scan running containers
   - Implement vulnerability patching strategies

## Compliance and Auditing

1. **Compliance frameworks**
   - Map container controls to compliance requirements (PCI-DSS, HIPAA, etc.)
   - Implement automated compliance checks

2. **Audit logging**
   - Enable comprehensive audit trails
   - Protect audit logs from tampering

```yaml
# Kubernetes API server audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["pods"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach"]
```

## Security Tools and Resources

### Container Security Scanning

1. **Image Scanners**
   - Trivy
   - Clair
   - Snyk Container
   - Anchore Engine
   - Docker Scout

2. **Runtime Security**
   - Falco
   - Sysdig Secure
   - Aqua Security
   - NeuVector
   - StackRox/Red Hat Advanced Cluster Security

3. **Policy Enforcement**
   - OPA/Gatekeeper
   - Kyverno
   - Kubewarden
   - K-Rail

### Secure Configuration Frameworks

1. **CIS Benchmarks**
   - Docker CIS Benchmark
   - Kubernetes CIS Benchmark

2. **NIST Publications**
   - NIST SP 800-190: Application Container Security Guide

3. **Security Practices**
   - OWASP Docker Security Cheat Sheet
   - Kubernetes Security Best Practices

## Further Recommendations

1. **Update regularly**
   - Maintain patched base images
   - Implement automated rebuild pipelines

2. **Implement security testing in CI/CD**
   - Integration with vulnerability scanners
   - Automated policy validation

3. **Security training**
   - Train developers on container security best practices
   - Regular security awareness sessions
