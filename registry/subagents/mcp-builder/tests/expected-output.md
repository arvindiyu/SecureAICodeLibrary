# mcp-builder — expected output (happy path)

## Pre-write plan surfaced for approval

```
mcp-builder plan
================
Target dir : mcp/support-tools/
Language   : python
Auth model : oauth-on-behalf-of
Tools      : 2 (search_kb low-impact, create_ticket medium-impact)

Files to write (10 total, ~9 KB):
  mcp/support-tools/README.md                (~2.0 KB)
  mcp/support-tools/pyproject.toml           (~0.6 KB)
  mcp/support-tools/src/__init__.py          (~0.05 KB)
  mcp/support-tools/src/audit.py             (~0.7 KB)
  mcp/support-tools/src/auth.py              (~1.2 KB)
  mcp/support-tools/src/server.py            (~1.4 KB)
  mcp/support-tools/src/tools/__init__.py    (~0.05 KB)
  mcp/support-tools/src/tools/search_kb.py   (~0.9 KB)
  mcp/support-tools/src/tools/create_ticket.py (~1.0 KB)
  mcp/support-tools/tests/test_search_kb.py    (~0.6 KB)
  mcp/support-tools/tests/test_create_ticket.py (~0.6 KB)

Approve write of 11 files under mcp/support-tools/? (yes / no / list)
```

## After approval — `README.md` skeleton

```markdown
# support-tools — MCP server

## Purpose

Expose KB search and ticket creation to coding agents on behalf of the caller.
Caller identity is enforced via OAuth on-behalf-of token exchange.

## Tools

| Name | Classification | Side effects | Auth |
|---|---|---|---|
| `search_kb` | low-impact | none | OBO |
| `create_ticket` | medium-impact | writes-external | OBO + human approval |

## Auth model

OAuth on-behalf-of (per `agentic-obo-auth`). The server never uses its own
credentials to act on behalf of the caller. Token exchange is implemented in
`src/auth.py`.

## Environment variables

| Name | Purpose |
|---|---|
| `OBO_TOKEN_ENDPOINT` | URL of the IdP's `/token` endpoint. |
| `OBO_CLIENT_ID` | This server's client ID. |
| `OBO_CLIENT_SECRET` | This server's client secret (vault-loaded). |
| `KB_BASE_URL` | KB API base URL. |
| `TRACKER_BASE_URL` | Issue-tracker API base URL. |

## Audit-log contract

Every tool invocation appends one JSON-lines entry to `.securecode/audit.log`
with the 10 mandatory fields plus `tool_name`.

## Kill-switch

Set `MCP_KILL_SWITCH=1` to refuse all tool calls. Per `ai-kill-switch`.

## Operational runbook

(see SUBAGENT-FLOWS.md for the canonical pattern; populate post-deploy.)

## References

- `mcp-server-safety`
- `agentic-tool-scoping`
- `agentic-obo-auth`
- `agentic-action-classification`
- `agentic-bulk-limits`
- `agentic-human-approval`
- `ai-audit-logging`
```

## Audit-log line appended to `.securecode/audit.log`

```json
{"timestamp":"2026-06-10T19:42:13Z","subagent_id":"mcp-builder","tier":"A","user":"dev","inputs_hash":"sha256:abc...","model":"<model-id>","token_in":3140,"token_out":2870,"decision":"pass","finding_count":0}
```

## Decision matrix

| User response | Files written | Audit-log decision |
|---|---|---|
| `yes` | 11 (alphabetical order) | `pass` |
| `no` | 0 | `denied-by-user` |
| `list` | 0; subagent re-prints plan | `awaiting-approval` |
