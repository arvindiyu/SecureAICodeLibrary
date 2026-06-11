# External Resources — AI-Centric Reference Index

> **Phase 5 — fully populated.** This document is the canonical external-reference index for the Secure AI Code Library. Each row carries a **"What AI typically gets wrong"** column: the unique AI-centric reframe that gives this document value beyond a plain link list.
>
> Every URL below is on the [`docs/SOURCES.md`](./SOURCES.md) allowlist. Last verified: **2026-06-10**.

**Cross-links:**
- [`README.md`](../README.md) § Catch-all subagent pattern — use `secure-developer-mentor` for topics not in this index.
- [`AGENTS.md`](../AGENTS.md) § What to do when a topic is not in the catalogue.
- [`registry/INDEX.md`](../registry/INDEX.md) — rule discovery (one row per rule ID + summary).
- [`docs/SUBAGENT-FLOWS.md`](./SUBAGENT-FLOWS.md) § `secure-developer-mentor` — catch-all invocation pattern.

---

## AI Security & Governance

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| OWASP LLM Top 10 (2025) | AI Security | AI forgets that LLM01 (Prompt Injection) applies to both direct and indirect vectors; omits output trust-boundary validation (LLM05); conflates LLM02 (Insecure Output Handling) with generic XSS without accounting for function-call outputs | https://genai.owasp.org/llm-top-10/ | 2026-06-10 |
| OWASP AI Exchange | AI Security | AI generates data-pipeline code without distinguishing security controls from privacy controls; omits data-poisoning mitigations for training workflows; skips threat scenarios for retrieval-augmented pipelines | https://owaspai.org/ | 2026-06-10 |
| MITRE ATLAS | AI Threat Intelligence | AI doesn't model adversarial-ML attack chains end-to-end; skips supply-chain attacks on model artifacts (AML.T0010); treats ATLAS as optional context instead of a required threat-enumeration step before shipping any agentic feature | https://atlas.mitre.org/ | 2026-06-10 |
| NIST AI Risk Management Framework 1.0 | AI Governance | AI omits GOVERN and MAP risk functions; generates MEASURE controls without corresponding MANAGE remediation loops; treats AI RMF as a one-time checklist rather than a continuous-improvement lifecycle | https://www.nist.gov/itl/ai-risk-management-framework | 2026-06-10 |
| NIST AI 600-1 (GenAI Profile) | AI Governance | AI ignores dual-use risks for generative model outputs; skips transparency disclosures required by the GenAI profile; fails to document data-provenance for training and fine-tuning datasets | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | 2026-06-10 |
| ISO/IEC 42001:2023 | AI Governance | AI generates AI-policy documents that omit impact-assessment procedures (A.6.1) and human-oversight requirements (A.9.3); conflates ISO 27001 information-security controls with ISO 42001 AI-management controls | https://www.iso.org/standard/81230.html | 2026-06-10 |
| EU AI Act (Regulation (EU) 2024/1689) | AI Regulation | AI skips risk-classification of the system under development; omits conformity-assessment obligations for high-risk systems (Art. 43); generates AI system documentation that omits intended-purpose statements required under Art. 13 | https://eur-lex.europa.eu/eli/reg/2024/1689/oj | 2026-06-10 |
| CSA AI Safety Initiative | AI Governance | AI treats CSA guidance as a normative standard rather than background framing; omits pairing with OWASP/NIST/ISO anchors required by ADR 0004; generates "CSA-compliant" claims without cross-referencing measurable controls | https://cloudsecurityalliance.org/research/topics/artificial-intelligence | 2026-06-10 |

---

## Secure Coding Standards

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| OWASP Application Security Verification Standard (ASVS) v5 | Secure Coding | AI references outdated ASVS v4 control numbers; skips level verification (L1/L2/L3) when generating acceptance criteria; generates ASVS traceability matrices without assigning control owners | https://owasp.org/www-project-application-security-verification-standard/ | 2026-06-10 |
| OWASP Cheat Sheet Series | Secure Coding | AI picks the nearest-sounding cheat sheet rather than the correct one (e.g., using the generic Input Validation Cheat Sheet when the framework has a dedicated one); omits cheat-sheet version context; copies code examples without adapting them to the project's framework version | https://cheatsheetseries.owasp.org/ | 2026-06-10 |
| CWE / CWE Top 25 Most Dangerous Software Weaknesses | Secure Coding | AI treats CWE IDs as interchangeable with CVE IDs; references child CWEs without tracing to parent weaknesses relevant to the code pattern; skips CWE-20 (Improper Input Validation) as an umbrella when generating validators | https://cwe.mitre.org/ | 2026-06-10 |
| NIST SP 800-218 (Secure Software Development Framework) | Secure Coding | AI generates SSDF-mapped controls only for the code layer, ignoring PO (Prepare the Organization) and RV (Responding to Vulnerabilities) practice groups; produces SSDF self-assessment templates without evidence pointers | https://csrc.nist.gov/publications/detail/sp/800-218/final | 2026-06-10 |
| NIST CSF 2.0 | Secure Coding | AI applies Identify/Protect/Detect/Respond/Recover functions only to infrastructure, not to application-layer controls; omits the new GOVERN function (added in CSF 2.0) when generating security program documentation | https://www.nist.gov/cyberframework | 2026-06-10 |

---

## Supply Chain

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| CycloneDX 1.5 | Supply Chain | AI generates SBOMs with missing `purl` fields; omits transitive dependencies; conflates component type `library` with `framework`; does not include VEX (Vulnerability Exploitability eXchange) data when generating patch-status reports | https://cyclonedx.org/specification/overview/ | 2026-06-10 |
| SPDX 2.3 / 3.0 | Supply Chain | AI mixes SPDX 2.x and 3.0 field names in the same document; omits `NOASSERTION` for unknown license fields instead of leaving them blank (which is invalid); skips relationship types when generating SBOM dependency graphs | https://spdx.dev/ | 2026-06-10 |
| SLSA v1.0 | Supply Chain | AI conflates SLSA build levels (L1/L2/L3) with maturity ratings; generates build pipelines without provenance attestation; omits the source-integrity track (SLSA Source L2+) when generating CI workflows for regulated environments | https://slsa.dev/ | 2026-06-10 |
| in-toto | Supply Chain | AI skips in-toto link metadata generation in CI steps; generates supply-chain policies without defining step functionaries; conflates in-toto attestations with SLSA provenance (they complement each other) | https://in-toto.io/ | 2026-06-10 |
| OpenSSF Scorecard | Supply Chain | AI generates Scorecard configuration that skips the `Token-Permissions` and `Pinned-Dependencies` checks; omits the `SAST` check when no static-analysis tool is configured; treats a low Scorecard score as informational rather than a blocking signal for high-risk repos | https://openssf.org/ | 2026-06-10 |

---

## IDE-Specific

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| Cursor Rules Documentation | IDE / AI Controls | AI generates `.cursor/rules/*.mdc` files without `globs` frontmatter, causing rules to always-apply and inflate context; omits `alwaysApply: false` for non-critical rules; generates rule files that exceed the 500-token summary budget defined in TOKEN-ECONOMICS.md | https://docs.cursor.com/context/rules | 2026-06-10 |
| GitHub Copilot Custom Instructions | IDE / AI Controls | AI generates `copilot-instructions.md` files that exceed 2 K tokens (the effective context limit); inlines full rule bodies instead of summaries; ignores per-repository instruction scoping; does not cross-reference the library's `registry/INDEX.md` for rule discovery | https://docs.github.com/en/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot | 2026-06-10 |
| Anthropic Claude Code (CLAUDE.md / subagent docs) | IDE / AI Controls | AI generates `CLAUDE.md` files that omit tool-scope restrictions; grants shell access without human-approval gates; does not define a `token_budget` per the library's subagent contract (deferred to M8 adapter — see `docs/MYTHOS.md`) | https://docs.anthropic.com/en/docs/agents | 2026-06-10 |
| Windsurf Rules Documentation | IDE / AI Controls | AI generates `.windsurfrules` without syntax validation; omits glob-scoping directives; conflates Windsurf rule syntax with Cursor `.mdc` syntax (they differ); does not cross-reference the library's `registry/INDEX.md` (Windsurf adapter deferred to M8) | https://docs.codeium.com/windsurf/ | 2026-06-10 |

---

## Per-Language Security Guides

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| Python — bandit (SAST) | Python Security | AI runs `bandit` without configuring a baseline file, causing noise from first run; skips severity/confidence filter (`-l`, `-i` flags); treats B101 (`assert`) findings as false positives and suppresses them globally instead of per-call-site | https://bandit.readthedocs.io/ | 2026-06-10 |
| Python — safety / pip-audit (SCA) | Python Security | AI pins all dependencies to exact versions without a Dependabot/Renovate policy, making updates manual; calls `safety check` with `--full-report` but ignores exit codes in CI; uses `safety` and `pip-audit` interchangeably without knowing their differing database sources | https://safety.security/ | 2026-06-10 |
| Node.js — npm audit (SCA) | Node.js Security | AI runs `npm audit` without `--audit-level=high`, causing CI to pass on high-severity findings; calls `npm audit fix --force` which can introduce breaking major-version upgrades; omits lockfile audit for monorepos (each workspace needs its own audit) | https://docs.npmjs.com/cli/commands/npm-audit | 2026-06-10 |
| Node.js — Snyk (SCA + SAST) | Node.js Security | AI generates Snyk policy files that ignore all vulnerabilities of a given severity rather than specific CVEs; omits the `--all-projects` flag in monorepos; conflates `snyk test` (point-in-time) with `snyk monitor` (continuous) | https://docs.snyk.io/ | 2026-06-10 |
| Java — OWASP Dependency-Check (SCA) | Java Security | AI configures Dependency-Check without a NVD API key, causing rate-limit failures; skips the `failBuildOnCVSS` threshold; does not suppress false positives with a documented suppression file — it either suppresses everything or nothing | https://owasp.org/www-project-dependency-check/ | 2026-06-10 |
| Go — govulncheck | Go Security | AI runs `govulncheck ./...` without understanding that it only reports reachable vulnerabilities (not all transitive); omits govulncheck from CI `go test` pipelines; treats a zero exit code as "no vulnerabilities" rather than "no reachable vulnerabilities" | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | 2026-06-10 |
| Rust — cargo-audit (SCA) | Rust Security | AI omits `cargo audit` from CI; does not configure `deny.toml` for advisory categories; conflates `cargo audit fix` (advisory-only) with `cargo update` (all semver-compatible updates) | https://rustsec.org/ | 2026-06-10 |
| TypeScript — compiler strict mode | TypeScript Security | AI generates `tsconfig.json` without `"strict": true`; skips `noImplicitAny` and `strictNullChecks` which catch entire classes of injection-adjacent type errors; adds `// @ts-ignore` comments instead of fixing type errors | https://www.typescriptlang.org/tsconfig/ | 2026-06-10 |
| C# — .NET security analyzers | C# / .NET Security | AI skips `Microsoft.CodeAnalysis.NetAnalyzers` package; generates code that passes string format arguments unsanitized; uses `BinaryFormatter` (deprecated, insecure) instead of `System.Text.Json`; omits nullable reference type annotations (`#nullable enable`) | https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview | 2026-06-10 |
| Ruby — bundler-audit (SCA) | Ruby Security | AI omits `bundle exec bundler-audit check --update` from CI; does not update the advisory database before auditing; conflates `bundler-audit` with `brakeman` (SAST) — both are needed | https://github.com/rubysec/bundler-audit | 2026-06-10 |

---

## Per-Framework AI Pitfalls

> This section is the primary reference for `registry/framework-specs/*.spec.yaml`. Each row notes "What AI typically gets wrong" for the most-generated patterns in that framework. The spec sheet carries secure-default metadata; this table is the human-readable rationale.

| Resource | Category | What AI typically gets wrong | Authoritative URL | Last verified |
|---|---|---|---|---|
| React | Frontend Framework | AI commonly emits `dangerouslySetInnerHTML` with unsanitized props; forgets `key` collision risks in dynamic lists; uses `useEffect` for data fetching without abort/cleanup; stores JWTs in `localStorage` instead of httpOnly cookies; omits CSP nonce handling for inline event handlers | https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html | 2026-06-10 |
| Angular | Frontend Framework | AI uses `bypassSecurityTrustHtml()` without verifying bypass necessity; generates `[innerHTML]` bindings that skip DomSanitizer; disables `XSRF_STRATEGY` for REST endpoints; uses deprecated `HttpClientModule` patterns that bypass interceptors; stores auth tokens in `sessionStorage` without considering shared-origin risks | https://angular.dev/best-practices/security | 2026-06-10 |
| Vue.js | Frontend Framework | AI uses `v-html` with unfiltered server data; misses `vm.$set` reactivity traps that can expose stale sensitive values; generates `axios` calls without CSRF headers; uses `vue-router` navigation guards without covering async resolution edge cases | https://vuejs.org/guide/best-practices/security.html | 2026-06-10 |
| Svelte / SvelteKit | Frontend Framework | AI uses `{@html}` with user-supplied content without sanitization; forgets that Svelte's template auto-escaping does NOT apply to `{@html}` blocks; omits CSP nonce configuration for SSR builds; generates SvelteKit `+server.ts` handlers without CSRF token validation | https://kit.svelte.dev/docs/introduction | 2026-06-10 |
| React Native | Mobile Framework | AI stores sensitive data in `AsyncStorage` (plaintext, unencrypted); uses `WebView` without `originWhitelist`; skips certificate pinning for API requests; logs sensitive data via `console.log` in production; uses `Linking.openURL` without validating URL schemes (deep-link injection) | https://reactnative.dev/docs/security | 2026-06-10 |
| Django | Backend Framework | AI disables CSRF middleware for API endpoints instead of using DRF token/session auth; uses `.raw()` SQL queries with string interpolation instead of ORM parameterized queries; sets `DEBUG=True` in generated settings files; hardcodes `SECRET_KEY`; skips `SECURE_SSL_REDIRECT` and `SECURE_HSTS_SECONDS` in production settings | https://docs.djangoproject.com/en/stable/topics/security/ | 2026-06-10 |
| Flask | Backend Framework | AI omits `SECRET_KEY` or uses a hardcoded placeholder; uses `render_template_string()` with user input (SSTI vector); returns raw `request.args` values without Pydantic/WTForms validation; skips `flask-wtf` CSRF protection; generates `app.run(debug=True)` for "convenience" | https://flask.palletsprojects.com/en/latest/security/ | 2026-06-10 |
| FastAPI | Backend Framework | AI uses `Query(...)` or `Path(...)` parameters without Pydantic constraint validators; allows `*` CORS origins without auth restriction; omits rate limiting on authentication endpoints; injects user-controlled strings into subprocess calls; generates `HTTPBasic` auth without constant-time comparison | https://fastapi.tiangolo.com/tutorial/security/ | 2026-06-10 |
| Express.js | Backend Framework | AI uses `eval(req.body)` patterns copied from old tutorials; places authentication middleware after body parsing (wrong order); omits `helmet()` security headers; returns `res.json(req.body)` without input validation (object mirroring); uses string concatenation in SQL queries | https://expressjs.com/en/advanced/best-practice-security.html | 2026-06-10 |
| Spring Boot | Backend Framework | AI disables Spring Security auto-configuration for convenience; exposes actuator endpoints without authentication; applies `@PreAuthorize` inconsistently (omits it on new controller methods); enables Jackson polymorphic deserialization gadgets; hardcodes credentials in `application.properties` | https://docs.spring.io/spring-security/reference/ | 2026-06-10 |
| ASP.NET Core | Backend Framework | AI disables antiforgery token validation on form endpoints; generates `[AllowAnonymous]` annotations without access-scope justification; uses `Response.WriteAsync(userInput)` without HTML-encoding; stores connection strings in `appsettings.json` instead of environment variables or Azure Key Vault | https://learn.microsoft.com/en-us/aspnet/core/security/ | 2026-06-10 |
| Ruby on Rails | Backend Framework | AI uses `html_safe` without explicit sanitization (`sanitize()` helper); generates `params.permit!` mass-assignment (permits all fields); disables `protect_from_forgery`; uses string interpolation in `find_by_sql`; stores secrets in initializers instead of Rails credentials or environment variables | https://guides.rubyonrails.org/security.html | 2026-06-10 |
| Gin (Go) | Backend Framework | AI uses `c.ShouldBind()` without struct validation tags (`binding:"required,max=..."`); exposes `/debug/pprof` endpoints in production mode; returns `c.JSON(200, request)` mirroring raw input; omits rate-limiting middleware; uses `c.Param()` values directly in file paths (path traversal) | https://cheatsheetseries.owasp.org/cheatsheets/Go_SCP_OWASP.html | 2026-06-10 |
| LangChain | AI Framework | AI concatenates user input directly into prompt templates without escaping or input-length limits; over-grants tool access without defining a restricted `ToolNode` allowlist; omits retry/timeout configuration on LLM calls; stores API keys in source code; skips output-parser validation, trusting raw LLM text as structured data | https://python.langchain.com/docs/security | 2026-06-10 |
| LlamaIndex | AI Framework | AI skips document-level access control in vector-store retrieval (all users can retrieve all nodes); exposes raw node metadata (including source file paths) to end users; uses default chunking strategies that split adjacent PII fields across chunk boundaries; omits ingestion-time content sanitization before embedding | https://cheatsheetseries.owasp.org/cheatsheets/LLM_AI_Security_Cheat_Sheet.html | 2026-06-10 |

---

## How to use this document

1. **Find your topic** in the relevant section above.
2. **Review the "What AI typically gets wrong" column** before accepting any AI-generated code for the topic.
3. **Run the appropriate subagent:**
   - Framework code → `coding-standards-reviewer` with `--framework=<id>` and the matching `registry/framework-specs/<id>.spec.yaml`.
   - Security architecture / AI feature → `ai-governance-auditor` against `registry/rules/ai-governance/`.
   - Unknown topic → `secure-developer-mentor` (catch-all; see [`README.md`](../README.md) § Catch-all pattern).
4. **If this document does not cover your topic**, invoke `secure-developer-mentor` with the closest framework-spec + applicable language rule; cite the relevant OWASP cheat sheet; flag the finding as `coverage: synthesized` so reviewers can promote it to a real spec sheet later.

---

_Last populated: Phase 5 — 2026-06-10. All URLs verified against `docs/SOURCES.md` allowlist._
