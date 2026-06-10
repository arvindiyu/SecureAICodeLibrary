# coding-standards-reviewer — expected output (happy path)

## Tier C SARIF on stdout

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "coding-standards-reviewer",
          "version": "1.0.0",
          "informationUri": "https://github.com/arvindiyu/SecureAICodeLibrary",
          "properties": { "lang_hint": "" }
        }
      },
      "results": [
        {
          "ruleId": "sql-injection-prevention",
          "level": "error",
          "message": { "text": "String-interpolated SQL detected. Use parameterized queries." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/db/users.ts" },
                "region": { "startLine": 12 }
              }
            }
          ],
          "properties": { "severity": "critical" }
        },
        {
          "ruleId": "cryptography-standards",
          "level": "error",
          "message": { "text": "Weak/legacy crypto primitive. Use SHA-256+, AES-GCM/ChaCha20-Poly1305." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/auth/hash.py" },
                "region": { "startLine": 3 }
              }
            }
          ],
          "properties": { "severity": "high" }
        }
      ]
    }
  ]
}
```

## Audit-log line appended to `.securecode/audit.log`

```json
{"timestamp":"2026-06-10T19:42:13Z","subagent_id":"coding-standards-reviewer","tier":"C","user":"dev","inputs_hash":"sha256:abc...","model":null,"token_in":0,"token_out":0,"decision":"block","finding_count":2}
```

## Exit code

`1` (critical + high blocking findings).
