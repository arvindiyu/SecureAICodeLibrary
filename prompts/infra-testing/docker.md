# Secure Coding Prompt: Docker & Docker-Compose

## Purpose

This prompt guides you in implementing secure Docker and Docker Compose configurations. Use this prompt to generate Docker-related files that follow security best practices and avoid common vulnerabilities in containerized environments.

## Secure Docker Development Prompt

```
As a secure Docker developer, help me implement [CONTAINERIZATION GOAL] with security as a priority. 

Consider these security aspects in your implementation:
1. Container image security and minimization
2. Secure configuration of Docker files and compose files
3. Least privilege principle for containers and volumes
4. Network security and proper isolation
5. Secret management in Docker environments
6. Container hardening and security controls
7. Security scanning and vulnerability management
8. Resource constraints and DoS prevention
9. Logging and audit capabilities
10. Secure container orchestration

Technical requirements:
- Base images: [Alpine, Distroless, Debian, etc.]
- Application type: [Web, API, Database, etc.]
- Deployment environment: [Development, Production, etc.]
- Orchestration: [Docker Compose, Kubernetes, etc.]

Follow these Docker security best practices:
- Use minimal, official base images with specific version tags
- Run containers as non-root users with minimum required capabilities
- Implement proper layering to minimize image size
- Use multi-stage builds to reduce attack surface
- Configure read-only file systems where possible
- Implement health checks and resource limits
- Use secrets management instead of environment variables for sensitive data
- Scan images for vulnerabilities before deployment
```

## Security Considerations for Docker

### Container Image Security

- **Minimal Base Images**: Use Alpine, Distroless, or minimal Debian/Ubuntu images
- **Version Pinning**: Always specify exact versions for base images
- **Multi-stage Builds**: Use multi-stage builds to reduce final image size
- **Image Scanning**: Regularly scan images for vulnerabilities with tools like Trivy, Clair, or Snyk
- **Official Images**: Prefer official images from trusted sources

### Container Runtime Security

- **Non-root Users**: Always run containers as non-root users
- **Capability Dropping**: Drop all capabilities and add only required ones
- **Read-only File Systems**: Mount file systems as read-only where possible
- **Tmpfs Mounts**: Use tmpfs for temporary file storage
- **Resource Limits**: Set CPU, memory, and PID limits
- **No Privileged Mode**: Avoid running containers in privileged mode

### Docker Compose Security

- **Network Isolation**: Define custom networks with proper segmentation
- **Service Dependencies**: Properly define service dependencies
- **Volume Security**: Limit volume access with proper permissions
- **Environment Variable Management**: Use .env files or external secret stores
- **Healthchecks**: Implement health checks for all services

### Secret Management

- **Docker Secrets**: Use Docker Secrets for sensitive information
- **External Secret Stores**: Integrate with Vault, AWS Secrets Manager, etc.
- **Environment Variable Limitations**: Understand the risks of environment variables
- **Build-time Secrets**: Never include secrets at build time

## Example Implementation: Secure Web Application Docker Setup

### Dockerfile Example (Node.js application)

```dockerfile
# Multi-stage build for minimal final image
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application (if required)
RUN npm run build

# Create production image
FROM node:18-alpine

# Set environment variables
ENV NODE_ENV=production

# Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

# Set working directory
WORKDIR /app

# Copy from builder stage
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json

# Set proper permissions
RUN chown -R appuser:appuser /app

# Use non-root user
USER appuser

# Set health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node healthcheck.js || exit 1

# Define entrypoint
ENTRYPOINT ["node", "dist/server.js"]

# Run with the least necessary capabilities
# Note: This is applied when running the container, not in the Dockerfile
# docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  app:
    build: 
      context: .
      dockerfile: Dockerfile
    image: secure-app:latest
    container_name: secure-app
    restart: unless-stopped
    read_only: true  # Read-only file system
    tmpfs:
      - /tmp:size=50M  # Writable temporary directory
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    secrets:
      - app_secret
    ports:
      - "127.0.0.1:3000:3000"  # Bind to localhost only
    networks:
      - app_net
    depends_on:
      db:
        condition: service_healthy
    security_opt:
      - no-new-privileges:true  # Prevent privilege escalation
    cap_drop:
      - ALL  # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE  # Add only what's needed
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "node", "healthcheck.js"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  db:
    image: postgres:14-alpine
    container_name: secure-db
    restart: unless-stopped
    environment:
      POSTGRES_USER_FILE: /run/secrets/db_user
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      POSTGRES_DB: appdb
    volumes:
      - db_data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d:ro
    networks:
      - app_net
    secrets:
      - db_user
      - db_password
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G

networks:
  app_net:
    driver: bridge
    internal: false  # Set to true if the service doesn't need external network access
    ipam:
      driver: default
      config:
        - subnet: 172.28.0.0/16

volumes:
  db_data:
    driver: local

secrets:
  app_secret:
    file: ./secrets/app_secret.txt
  db_user:
    file: ./secrets/db_user.txt
  db_password:
    file: ./secrets/db_password.txt
```

## Security Testing for Docker

### Image Security Testing

- **Vulnerability Scanning**: 
  ```bash
  docker scan myimage:latest
  # or
  trivy image myimage:latest
  ```

- **Dockerfile Linting**:
  ```bash
  hadolint Dockerfile
  ```

- **CIS Docker Benchmark**:
  ```bash
  docker-bench-security
  ```

### Runtime Security Testing

- **Check for non-root user**:
  ```bash
  docker run --rm myimage:latest id
  ```

- **Inspect capabilities**:
  ```bash
  docker inspect --format='{{.HostConfig.CapDrop}}' container_name
  ```

- **Check for read-only file system**:
  ```bash
  docker inspect --format='{{.HostConfig.ReadonlyRootfs}}' container_name
  ```

## References

- Docker Security Documentation: https://docs.docker.com/engine/security/
- OWASP Docker Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
