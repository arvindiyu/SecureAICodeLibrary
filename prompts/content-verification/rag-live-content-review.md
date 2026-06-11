# RAG Live Content Review

> **Prompt ID:** `rag-live-content-review`  
> **Category:** Content Verification  
> **Subagent:** [`registry/subagents/ai-governance-auditor/`](../../registry/subagents/ai-governance-auditor/) (review findings) + [`registry/subagents/secure-developer-mentor/`](../../registry/subagents/secure-developer-mentor/) (remediation)  
> **Rules enforced:** `prompt-injection-prevention` · `ai-data-segregation` · `ai-data-classification` · `ai-audit-logging` · `agentic-human-approval`

---

## Purpose

Review a Retrieval-Augmented Generation (RAG) pipeline's content sources for three security properties:

1. **Prompt injection in stored documents** — malicious instructions embedded in indexed content that could hijack the LLM's behavior at retrieval time.
2. **Data classification compliance** — documents are labeled and retrieved in accordance with their sensitivity tier; confidential documents do not escape into public or cross-tenant retrieval contexts.
3. **Retrieval-time tenancy isolation** — one tenant's queries cannot retrieve another tenant's documents through semantic proximity or metadata leakage.

Run this review before going live with a new content source, after adding a new document ingestion pipeline, or after any change to the retrieval configuration.

---

## Input Requirements

Provide the following before starting the review:

```yaml
rag_pipeline:
  embedding_model: "text-embedding-3-large"   # model used for embedding
  vector_store: "pgvector | pinecone | weaviate | qdrant | chromadb | other"
  retrieval_top_k: 5                          # number of results returned per query
  reranker: "cohere | none | custom"          # post-retrieval reranker

content_sources:
  - name: "Customer Support Knowledge Base"
    type: "confluence | sharepoint | s3 | web-scrape | database | api | other"
    ingestion_schedule: "hourly | daily | on-change | manual"
    data_classification: "public | internal | confidential | restricted"

auth_context:
  multi_tenant: true   # are multiple tenants (orgs/users) isolated from each other?
  tenant_isolation_strategy: "metadata_filter | namespace | collection_per_tenant | none"
  user_auth_before_retrieval: true   # is the user authenticated before retrieval?
```

---

## Review Scope 1 — Prompt Injection in Stored Documents

> Rule: `prompt-injection-prevention`

### 1.1 — Ingestion-Time Sanitization

Does the ingestion pipeline sanitize documents for embedded instructions before storing vectors?

**Check list:**

- [ ] The ingestion pipeline strips or escapes patterns matching `Ignore previous instructions`, `<|system|>`, `<!-- ... -->` instruction blocks, and similar injection markers.
- [ ] Images embedded in documents are not OCR'd without sanitization of the extracted text.
- [ ] HTML/markdown from web scrapes is stripped to plain text before embedding (removes `<script>` and event handler injection via anchor text).
- [ ] Documents from external/untrusted sources are tagged with `source_trust: low` and are explicitly NOT included in system-prompt context — only in user-prompt context.
- [ ] The retrieval pipeline includes a **post-retrieval injection scan** before handing chunks to the LLM.

**Evidence required:**

```
Ingestion sanitizer component: _______________________________________________
Injection pattern regex/library: _______________________________________________
System-prompt vs. user-prompt context separation: YES / NO
Post-retrieval scan: YES / NO / PLANNED
```

### 1.2 — Retrieval Prompt Architecture

How are retrieved chunks inserted into the LLM context?

```python
# BAD: retrieved content in system prompt — injection controls the LLM's base behavior
system_prompt = f"""You are a helpful assistant.
Context:
{retrieved_chunks}  # DANGEROUS: attacker can embed instructions here
"""

# GOOD: retrieved content in user-turn, clearly delimited
system_prompt = "You are a helpful assistant. Answer only from the provided context."

user_message = f"""
<context>
{sanitize_for_prompt(retrieved_chunks)}
</context>

User question: {user_question}
"""
```

**Check:** Are retrieved chunks always placed in the user-turn (not the system prompt) when the content source is not fully trusted?

```
Retrieved chunks placement: system_prompt | user_turn | mixed
Trust tier of each source: _______________________________________________
```

---

## Review Scope 2 — Data Classification Compliance

> Rule: `ai-data-classification`

### 2.1 — Document Metadata Inventory

Every indexed document must carry a `data_classification` metadata field. Verify:

| Check | Status |
|---|---|
| All documents have a `data_classification` field in vector store metadata | ☐ |
| `restricted` documents are NOT in the same vector store namespace as `public` documents | ☐ |
| Retrieval queries filter by `data_classification` based on the caller's clearance level | ☐ |
| Embedding deletion is implemented for documents that are reclassified upward (e.g., `internal` → `confidential`) | ☐ |
| PII fields are detected and masked before embedding (e.g., SSN, credit card numbers stripped from text) | ☐ |

### 2.2 — Caller Clearance Enforcement

Does the retrieval layer enforce that a caller with clearance level X cannot retrieve documents with classification higher than X?

```python
# GOOD: enforce clearance at retrieval time
def retrieve(query: str, user_clearance: str, tenant_id: str) -> list[Document]:
    clearance_filter = {
        "public": ["public"],
        "internal": ["public", "internal"],
        "confidential": ["public", "internal", "confidential"],
        "restricted": ["public", "internal", "confidential", "restricted"],
    }[user_clearance]

    return vector_store.similarity_search(
        query,
        filter={
            "data_classification": {"$in": clearance_filter},
            "tenant_id": {"$eq": tenant_id},    # tenancy isolation (Scope 3)
        },
        k=top_k,
    )
```

```
Caller clearance enforcement: YES / NO / PARTIAL
Where enforced: retrieval_layer | application_layer | none
```

---

## Review Scope 3 — Retrieval-Time Tenancy Isolation

> Rule: `ai-data-segregation`

### 3.1 — Isolation Strategy Assessment

| Strategy | Isolation strength | Assessment |
|---|---|---|
| **Collection per tenant** | Strong — vectors physically separated | Recommended for `restricted` data |
| **Namespace per tenant** | Medium — logical separation within index | Acceptable for `confidential` |
| **Metadata filter** | Weak — relies on filter always being applied | Only for `public`/`internal` data |
| **No isolation** | None | Not acceptable for any multi-tenant deployment |

```
Current strategy: _______________________________________________
Data classification of most sensitive documents: _______________________________________________
Strategy sufficient for sensitivity level: YES / NO (see table above)
```

### 3.2 — Tenant Isolation Test Cases

Run the following test queries to verify isolation:

```python
# Test: can tenant A's query retrieve tenant B's documents?
result = retrieve(
    query="most sensitive business data",  # broad semantic query
    user_clearance="confidential",
    tenant_id="tenant_a",
)
assert all(doc.metadata["tenant_id"] == "tenant_a" for doc in result), \
    "FAIL: Cross-tenant data leaked via semantic search"

# Test: can a restricted document be retrieved by a user with internal clearance?
result = retrieve(
    query="executive compensation strategy",
    user_clearance="internal",
    tenant_id="tenant_a",
)
assert all(doc.metadata["data_classification"] != "restricted" for doc in result), \
    "FAIL: Restricted document retrieved by internal-clearance user"
```

### 3.3 — Metadata Leakage

Check that retrieved chunk metadata returned to the user does NOT include:

- [ ] Internal document IDs or chunk IDs that could be used for direct access bypass
- [ ] Other tenants' document titles or source paths (even in debugging/logging output)
- [ ] Raw vector similarity scores that could enable a timing attack to infer content

---

## Output Format

After completing the three scopes, produce a finding report in this format:

```yaml
review_id: "rag-review-<YYYY-MM-DD>"
pipeline: "<pipeline name>"
reviewer: "<your name / subagent ID>"
timestamp: "<ISO-8601>"
findings:
  - id: "RAG-001"
    scope: "prompt_injection | data_classification | tenancy_isolation"
    severity: "critical | high | medium | low"
    rule: "prompt-injection-prevention | ai-data-classification | ai-data-segregation"
    description: "..."
    evidence: "..."
    remediation: "..."
    status: "open | accepted_risk | remediated"
```

Report findings to: `ai-governance-auditor` subagent (for CI/pre-commit gate integration) or file as a JIRA ticket per [`docs/MANTHAN-CONTRACT.md`](../../docs/MANTHAN-CONTRACT.md).

---

## Rule Cross-References

| Rule ID | Enforced in scope |
|---|---|
| `prompt-injection-prevention` | Scope 1 — ingestion sanitization, retrieval context placement |
| `ai-data-classification` | Scope 2 — document metadata, clearance enforcement |
| `ai-data-segregation` | Scope 3 — tenancy isolation strategy, cross-tenant tests |
| `ai-audit-logging` | All scopes — log retrieval decisions + clearance-enforcement events |
| `agentic-human-approval` | Scope 2 — human review required before promoting a content source from dev to prod |

---

_Source allowlist: `docs/SOURCES.md` · Last updated: 2026-06-10_  
_Cross-references: [OWASP LLM Top 10 (2025) LLM01](https://genai.owasp.org/llm-top-10/) · [OWASP AI Exchange](https://owaspai.org/) · NIST AI RMF MAP-2.3_
