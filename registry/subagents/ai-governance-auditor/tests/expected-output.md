# ai-governance-auditor — expected output (happy path)

## Tier C SARIF on stdout (abbreviated)

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ai-governance-auditor",
          "version": "1.0.0",
          "informationUri": "https://github.com/arvindiyu/SecureAICodeLibrary"
        }
      },
      "results": [
        {
          "ruleId": "prompt-injection-prevention",
          "level": "error",
          "message": { "text": "LLM call without visible input sanitization." },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/llm/chat.py" } } }],
          "properties": { "severity": "critical" }
        },
        {
          "ruleId": "llm-output-sanitization",
          "level": "error",
          "message": { "text": "LLM output rendered without sanitization." },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/llm/chat.py" } } }],
          "properties": { "severity": "high" }
        },
        {
          "ruleId": "ai-audit-logging",
          "level": "error",
          "message": { "text": "LLM/agent call without an audit-log emission." },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/llm/chat.py" } } }],
          "properties": { "severity": "critical" }
        }
        /* additional findings for agentic-tool-scoping, ai-rate-limiting,
           ai-content-moderation, ai-guardrails, ai-human-oversight,
           ai-data-classification, ai-data-provenance, ai-explainability,
           ai-model-lifecycle, ai-bias-fairness, ai-third-party-ai,
           ai-regulatory-compliance, ai-data-segregation, ai-kill-switch,
           ai-code-provenance, agentic-action-classification,
           agentic-human-approval, agentic-bulk-limits, agentic-obo-auth */
      ]
    }
  ]
}
```

## Audit-log line appended to `.securecode/audit.log`

```json
{"timestamp":"2026-06-10T19:42:13Z","subagent_id":"ai-governance-auditor","tier":"C","user":"dev","inputs_hash":"sha256:abc...","model":null,"token_in":0,"token_out":0,"decision":"block","finding_count":21}
```

## Exit code

`1` (critical/high blocking findings).

## Tier A markdown gap summary (when `--explain`)

```markdown
## Findings by severity

- Critical: 2 (`prompt-injection-prevention`, `ai-audit-logging`)
- High:     6
- Medium:  10
- Low:      3

## Top remediation steps

- Sanitize user input before sending to the LLM (`prompt-injection-prevention`); use a strict template or escaping helper.
- Emit a `.securecode/audit.log` line for every LLM round-trip (`ai-audit-logging`). Required fields are listed in `AGENTS.md`.
- Sanitize/escape the LLM response before HTML interpolation (`llm-output-sanitization`); never f-string raw output into HTML.
- Add an explicit `tool_scope` allow-list and per-action bulk limits (`agentic-tool-scoping`, `agentic-bulk-limits`).
- Add a content-moderation step before the response leaves the boundary (`ai-content-moderation`).

## References

- `prompt-injection-prevention`
- `llm-output-sanitization`
- `ai-audit-logging`
- `agentic-tool-scoping`
- `agentic-bulk-limits`
- `ai-content-moderation`
- `ai-rate-limiting`
- ISO/IEC 42001:2023 §A.6, §A.9 (per `CONSTITUTION.md` §D)
- NIST AI RMF GenAI Profile MAP-2.3, MEASURE-2.7
- OWASP Top 10 for LLM Applications 2025: LLM01, LLM02, LLM06
```
