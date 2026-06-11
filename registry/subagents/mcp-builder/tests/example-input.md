# mcp-builder — example input (happy path)

## Scenario

A developer wants to scaffold a Python MCP server that exposes two tools — `search_kb` (low-impact retrieval) and `create_ticket` (medium-impact write to an issue tracker) — using OAuth on-behalf-of for caller identity.

## Native (Tier A) invocation

```
@mcp-builder --spec mcp/specs/support-tools.spec.yaml --out mcp/support-tools
```

## Spec file (`mcp/specs/support-tools.spec.yaml`)

```yaml
id: support-tools
name: Support Tools MCP Server
purpose: >-
  Expose KB search and ticket creation to coding agents on behalf of the
  caller. Caller identity is enforced via OAuth on-behalf-of token exchange.

tools:
  - name: search_kb
    purpose: Search internal KB articles. Read-only.
    inputs:
      query: { type: string, max_length: 200 }
    outputs:
      hits: { type: array, items: { id: string, title: string, score: number } }
    classification: low-impact
    side_effects: none

  - name: create_ticket
    purpose: Create a support ticket in the user's tracker.
    inputs:
      summary: { type: string, max_length: 200 }
      description: { type: string, max_length: 2000 }
      labels: { type: array, items: string, max_items: 5 }
    outputs:
      ticket_id: { type: string }
    classification: medium-impact
    side_effects: writes-external

auth_model: oauth-on-behalf-of
language: python
```

## Expected interactive flow

1. Subagent validates spec; all required fields present.
2. Subagent prints the plan (file list, byte estimates, target dir).
3. Subagent stops and asks for approval.
4. On `yes`, files are written in deterministic alphabetical order.
5. Audit-log line emitted (`decision: "pass"`, `finding_count: 0`).

## Files the scaffold should produce

```
mcp/support-tools/
├── README.md
├── pyproject.toml
├── src/
│   ├── __init__.py
│   ├── auth.py
│   ├── audit.py
│   ├── server.py
│   └── tools/
│       ├── __init__.py
│       ├── search_kb.py
│       └── create_ticket.py
└── tests/
    ├── test_search_kb.py
    └── test_create_ticket.py
```
