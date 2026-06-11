# adr-author — example input (happy path)

## Scenario

A developer stages a diff that introduces a new top-level `cache/` directory and modifies `package.json` to add `redis: ^5.0.0` as a runtime dependency. No file under `docs/adr/` was touched.

## Native (Tier A) invocation

```
@adr-author
```

with the staged diff visible to Cursor.

## Headless (Tier C) invocation

```bash
git add cache/ package.json
registry/subagents/adr-author/run.sh --output-format sarif
```

## Staged-diff snapshot (input the runner sees)

```diff
diff --git a/cache/redis_client.ts b/cache/redis_client.ts
new file mode 100644
+++ b/cache/redis_client.ts
@@ -0,0 +1,10 @@
+import Redis from 'redis';
+export const client = Redis.createClient();

diff --git a/package.json b/package.json
@@ -10,6 +10,7 @@
   "dependencies": {
+    "redis": "^5.0.0"
   }
```

## Expected behaviour

- Architecture-impact fires on two reasons: `new-top-level-dir:cache` and `dependency-manifest:package.json`.
- No ADR was touched in the diff → `MISSING_ADR` is reported.
- Suggested filename: `docs/adr/0006-cache.md` (assuming five existing ADRs `0001…0005`).
- Exit code: `1`.
- One audit-log line appended to `.securecode/audit.log` with `decision: "block"`, `finding_count: 1`, `model: null`.
