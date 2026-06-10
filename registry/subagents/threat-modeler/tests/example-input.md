# threat-modeler — example input (happy path)

## Scenario

A developer adds a new FastAPI route under `src/api/orders.py` that talks to a newly-introduced PostgreSQL session, and does NOT touch `THREAT_MODEL.md`.

## Native (Tier A) invocation

```
@threat-modeler orders-api
```

## Headless (Tier C) invocation

```bash
git add src/api/orders.py src/db/session.py
registry/subagents/threat-modeler/run.sh --output-format sarif
```

## Staged-diff snapshot (input the runner sees)

```diff
diff --git a/src/api/orders.py b/src/api/orders.py
new file mode 100644
+++ b/src/api/orders.py
@@ -0,0 +1,12 @@
+from fastapi import APIRouter, Depends
+from src.db.session import get_session
+
+router = APIRouter()
+
+@router.post("/orders")
+def create_order(payload: dict, session = Depends(get_session)):
+    session.execute("INSERT INTO orders ...")
+    return {"status": "ok"}

diff --git a/src/db/session.py b/src/db/session.py
new file mode 100644
+++ b/src/db/session.py
@@ -0,0 +1,5 @@
+from sqlalchemy import create_engine
+engine = create_engine("postgresql://...")
```

## Expected behaviour

- Boundary triggers fire on two reasons: `new-http-endpoint` (FastAPI `@router.post`) and `new-persistence` (`sqlalchemy.create_engine`).
- `THREAT_MODEL.md` was not touched in the diff → `MISSING_THREAT_MODEL` is reported.
- SARIF output includes a Mermaid DFD skeleton and a STRIDE entry table in `properties`.
- Exit code: `1`.
- One audit-log line appended with `decision: "block"`, `finding_count: 1`, `model: null`.
