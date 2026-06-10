# coding-standards-reviewer — example input (happy path)

## Scenario

A developer stages a TypeScript change that interpolates user input into a SQL query and a separate Python change that uses MD5 for password hashing.

## Native (Tier A) invocation

```
@coding-standards-reviewer --lang=typescript
```
(or omit `--lang` to auto-detect)

## Headless (Tier C) invocation

```bash
git add src/db/users.ts src/auth/hash.py
registry/subagents/coding-standards-reviewer/run.sh --output-format sarif
```

## Staged-diff snapshot (input the runner sees)

```diff
diff --git a/src/db/users.ts b/src/db/users.ts
+++ b/src/db/users.ts
@@ -10,6 +10,8 @@
+export async function findUser(id: string) {
+  return db.query(`SELECT * FROM users WHERE id = ${id}`);
+}

diff --git a/src/auth/hash.py b/src/auth/hash.py
+++ b/src/auth/hash.py
@@ -1,3 +1,4 @@
 import hashlib
+def password_hash(p: str) -> str:
+    return hashlib.md5(p.encode()).hexdigest()
```

## Expected behaviour

- `src/db/users.ts` matches `sql-injection-prevention` antipattern (template-literal SQL) → critical finding.
- `src/auth/hash.py` matches `cryptography-standards` antipattern (`MD5`) → high finding.
- Both findings classified as blocking.
- Exit code: `1`.
- One audit-log line appended with `decision: "block"`, `finding_count: 2`, `model: null`.
