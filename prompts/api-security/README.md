# API Security Prompts

This directory contains prompts for secure API design and implementation. These prompts are designed to help developers create secure APIs that follow best practices for authentication, authorization, data validation, and other security considerations.

## Available Prompts

1. [API Design Security](./api-design-security.md) - Comprehensive guide for designing secure API endpoints

For authentication, authorization, data validation, and rate limiting guidance, see the consolidated
[External Resources → Backend Frameworks](../../docs/EXTERNAL-RESOURCES.md#backend-frameworks) section
and invoke the `coding-standards-reviewer` subagent with applicable rules:
`auth-patterns`, `access-control`, `input-validation`, `cors-security`.

## Usage

Each prompt file contains:

1. A detailed prompt for GitHub Copilot to generate secure API code
2. Example implementations in multiple programming languages
3. Security testing guidelines
4. Common security vulnerabilities to watch for

Use these prompts when designing and implementing APIs to ensure that security is a priority from the beginning.
