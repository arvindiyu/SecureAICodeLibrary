# adr-author — expected output (happy path)

## Tier C SARIF on stdout

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "adr-author",
          "version": "1.0.0",
          "informationUri": "https://github.com/arvindiyu/SecureAICodeLibrary",
          "rules": [
            {
              "id": "MISSING_ADR",
              "name": "MissingArchitecturalDecisionRecord",
              "shortDescription": { "text": "Architecture-impact change without an accompanying ADR." },
              "helpUri": "registry/rules/policies/required-artifacts.rule.yaml"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "MISSING_ADR",
          "level": "error",
          "message": {
            "text": "Architecture-impact detected (new-top-level-dir:cache,dependency-manifest:package.json) but no ADR was touched in this diff. Suggested file: docs/adr/0006-cache.md"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "docs/adr/0006-cache.md" }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Audit-log line appended to `.securecode/audit.log`

```json
{"timestamp":"2026-06-10T19:42:13Z","subagent_id":"adr-author","tier":"C","user":"dev","inputs_hash":"sha256:abc...","model":null,"token_in":0,"token_out":0,"decision":"block","finding_count":1}
```

## Exit code

`1` (blocking finding).

## Tier A draft surfaced for human approval

```markdown
# ADR 0006 — Adopt Redis as the cache backend

- **Status:** Proposed
- **Date:** 2026-06-10
- **Deciders:** <author>

## Context

The diff introduces a new top-level `cache/` directory and adds `redis: ^5.0.0` as a runtime dependency in `package.json`. This is the first persistent caching layer in the project. Per `required-artifacts`, an ADR is required when a new runtime dependency or new top-level directory lands.

## Decision

Use Redis 5.x as the in-process and cross-instance cache backend.

- Deployment via the team's existing managed Redis offering.
- Connection lifecycle owned by `cache/redis_client.ts`.
- TLS-only connections; secrets sourced from the existing vault adapter.

## Consequences

### Positive
- Sub-millisecond reads.
- Mature ecosystem with Node client.

### Negative
- Adds a new operational dependency.
- Requires a freshness check on the SBOM; `sbom-freshness` may flag this commit until `sbom.cdx.json` is regenerated.

### Neutral
- THREAT_MODEL.md trust boundaries gain a new persistence boundary.

## Follow-up

- Re-run `threat-modeler` to update STRIDE coverage for the new persistence boundary.
- Regenerate `sbom.cdx.json` (`make sbom`).
- Add a `secure-headers` rule reference once a public-facing endpoint consumes the cache.

## References

- OWASP ASVS v5 V14 — Configuration.
- ISO/IEC 27001:2022 Annex A.5.19 — Information security in supplier relationships.
```
