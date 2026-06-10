# ai-governance-auditor — example input (happy path)

## Scenario

A developer adds a new LLM-calling module under `src/llm/chat.py` that:
- Calls OpenAI without sanitizing user input.
- Renders the LLM response directly to HTML.
- Has no audit-log emission.

`THREAT_MODEL.md` and `.securecode/audit.log` are unchanged.

## Native (Tier A) invocation

```
@ai-governance-auditor
```

## Headless (Tier C) invocation

```bash
git add src/llm/chat.py
registry/subagents/ai-governance-auditor/run.sh --output-format sarif
```

## Staged-diff snapshot (input the runner sees)

```diff
diff --git a/src/llm/chat.py b/src/llm/chat.py
new file mode 100644
+++ b/src/llm/chat.py
@@ -0,0 +1,16 @@
+from openai import OpenAI
+
+client = OpenAI()
+
+def chat(user_input: str) -> str:
+    resp = client.chat.completions.create(
+        model="gpt-4o-mini",
+        messages=[
+            {"role": "system", "content": "You are a helpful agent."},
+            {"role": "user",   "content": user_input},
+        ],
+    )
+    return resp.choices[0].message.content
+
+def render(html_response: str) -> str:
+    return f"<div>{html_response}</div>"
```

## Expected behaviour

- File matches AI-glob (`**/llm/**`) AND body contains `openai` → audited.
- The runner pattern-checks all 23 rules. Findings fire on (at minimum):
  - `prompt-injection-prevention` (critical) — no sanitization of `user_input`.
  - `llm-output-sanitization` (high) — `f"<div>{html_response}</div>"` interpolation.
  - `ai-audit-logging` (critical) — no `.securecode/audit.log` write.
  - `agentic-tool-scoping` (high) — no explicit allow-list.
  - `ai-rate-limiting` (medium).
  - `ai-content-moderation` (high).
  - …and several other "absent guardrail" findings.
- ≥ 1 critical/high finding → `decision: block`, exit code `1`.
- One audit-log line appended with `model: null`, `token_in: 0`, `token_out: 0`, `finding_count: <N>`.
