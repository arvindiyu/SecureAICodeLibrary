# Cloud Security Prompts

This directory contains prompts for secure cloud infrastructure configuration. These prompts are designed to help developers and DevOps engineers create secure cloud resources that follow best practices for identity management, network security, encryption, monitoring, and compliance.

## Available Prompts

1. [AWS Security Configuration](./aws-security.md) - Comprehensive guide for securing AWS resources
2. [GCP Security Configuration](./gcp-security.md) - Comprehensive guide for securing GCP resources
3. [Terraform Security](./terraform-security.md) - Security best practices for Terraform infrastructure as code

For Azure and Kubernetes security guidance, see the consolidated
[External Resources → Cloud Infrastructure](../../docs/EXTERNAL-RESOURCES.md#cloud-infrastructure) section
and invoke the `coding-standards-reviewer` subagent with the `secure-configuration` rule.

## Usage

Each prompt file contains:

1. A detailed prompt for GitHub Copilot to generate secure cloud infrastructure code
2. Example implementations using infrastructure as code tools
3. Security best practices checklists
4. Common security misconfigurations to watch for

Use these prompts when designing and implementing cloud infrastructure to ensure that security is a priority from the beginning.
