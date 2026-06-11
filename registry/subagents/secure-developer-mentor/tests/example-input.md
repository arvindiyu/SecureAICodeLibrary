# secure-developer-mentor — example input (happy path)

## Scenario

A developer asks the mentor whether storing a JWT in `localStorage` is safe and pastes a snippet.

## Native (Tier A) invocation

```
@secure-developer-mentor "Is it safe to store a JWT in localStorage for this React app?"
```

## Code snippet pasted alongside

```ts
// src/auth/store.ts
export function saveToken(token: string) {
  localStorage.setItem("jwt", token);
}

export function getToken(): string | null {
  return localStorage.getItem("jwt");
}
```

## Expected behaviour

- Mentor reads `registry/INDEX.md` once.
- Identifies the closest applicable rules:
  - `session-management` (cookie attributes)
  - `auth-patterns` (JWT handling)
  - per-language `typescript-security` (extends one of the above) if present.
- Returns a markdown answer with the canonical structure.
- Does not echo the JWT value (treats the snippet as untrusted; the snippet has no real value here, but the protocol is the same).
- Audit-log line emitted (`decision: "pass"`, `finding_count: 0`).
