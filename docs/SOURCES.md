# Sources

> The verifiable-source allowlist. Every threat-intel citation, standard citation, and regulatory citation in this repository MUST resolve to an entry below. CI workflow `source-hygiene.yml` (Phase 6) regex-cross-references citations against this file and blocks PRs that introduce sources outside the allowlist (or that cite vendor announcements as threat statistics).

This file is the operational expression of [ADR 0004](./adr/0004-claim-hygiene-and-sourcing.md). Add a new source by opening a PR that (a) appends it here with a citation pattern and a justification, and (b) updates `source-hygiene.yml`'s regex set if needed.

## Citation format requirements

Every citation in repository markdown must satisfy at least one of:

1. **URL form** — a direct URL to a primary source on the allowlist below.
2. **Dated form** — a dated reference (`(YYYY)`, `Source, YYYY`, or `as of YYYY-MM-DD`).
3. **Standard-ID form** — `OWASP ASVS v5 §X.Y`, `ISO/IEC 27001:2022 A.5.17`, `NIST SP 800-218`, `NIST AI RMF GOVERN-1.1`, `CWE-89`, `AML.T0051`, etc.

Threat-statistic claims (numeric counts, percentages, dwell times, breach rates) MUST cite a dated public primary source from the **Threat-intel reports** section below.

## Allowlist

### Threat-intel reports (dated, public, primary)

| Source | Citation pattern | Domain | Status |
|---|---|---|---|
| **Mandiant M-Trends** | `Mandiant M-Trends YYYY` (with page or section ref) | cloud.google.com / mandiant.com | Allowed for breach-trend statistics; dated annual report. |
| **Verizon Data Breach Investigations Report (DBIR)** | `Verizon DBIR YYYY` (with section ref) | verizon.com/business/resources | Allowed for breach-frequency statistics. |
| **CrowdStrike Global Threat Report (GTR)** | `CrowdStrike GTR YYYY` (with section ref) | crowdstrike.com | Allowed for adversary tradecraft and timing data. |
| **Microsoft Digital Defense Report (DDR)** | `Microsoft DDR YYYY` | microsoft.com | Allowed for telemetry-derived statistics. |
| **Google Threat Analysis Group (TAG)** | `Google TAG bulletin, YYYY-MM-DD` | blog.google/threat-analysis-group | Allowed for state-actor and 0-day reporting. |
| **CISA advisories** | `CISA AAYY-NNNA` | cisa.gov/news-events/cybersecurity-advisories | Allowed for confirmed advisories; cite the advisory ID. |
| **ENISA Threat Landscape** | `ENISA Threat Landscape YYYY` | enisa.europa.eu/topics/cyber-threats | Allowed for European threat-landscape statistics. |
| **MITRE ATT&CK** | `ATT&CK technique T####` (with version, e.g. `v15 (2024)`) | attack.mitre.org | Allowed for adversary technique identification. |
| **MITRE ATLAS** | `AML.T#####` (with version, e.g. `ATLAS (2024)`) | atlas.mitre.org | Allowed for adversarial-ML technique identification. |

### Standards (primary)

| Source | Citation pattern | Domain | Status |
|---|---|---|---|
| **OWASP Application Security Verification Standard (ASVS) v5** | `OWASP ASVS v5 §X.Y.Z` | owasp.org/www-project-application-security-verification-standard | Allowed; primary anchor for `coding-standards` rules. |
| **OWASP Top 10 for LLM Applications** | `OWASP Top 10 for LLM Applications (2025) LLM##` | genai.owasp.org/llm-top-10 | Allowed; primary anchor for LLM-specific AI-governance rules. |
| **OWASP Cheat Sheets** | URL to specific cheat sheet | cheatsheetseries.owasp.org | Allowed; supplementary guidance, not normative. |
| **ISO/IEC 27001:2022** | `ISO/IEC 27001:2022 A.X.YY` | iso.org/standard/27001 | Allowed; primary anchor for ISMS controls. |
| **ISO/IEC 42001:2023** | `ISO/IEC 42001:2023 A.X.Y` | iso.org/standard/81230.html | Allowed; primary anchor for AI management system controls. |
| **NIST AI Risk Management Framework (AI RMF 1.0)** | `NIST AI RMF GOVERN-X.Y`, `MAP-X.Y`, `MEASURE-X.Y`, `MANAGE-X.Y` | nist.gov/itl/ai-risk-management-framework | Allowed; primary anchor for AI risk functions. |
| **NIST AI RMF GenAI Profile (NIST AI 600-1)** | `NIST AI 600-1 (2024) §X.Y` | nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | Allowed; companion to AI RMF for generative AI. |
| **NIST SSDF (SP 800-218)** | `NIST SP 800-218 PO.X` / `PS.X` / `PW.X` / `RV.X` | csrc.nist.gov/publications/detail/sp/800-218/final | Allowed for secure development practices. |
| **NIST CSF 2.0** | `NIST CSF 2.0 FUNCTION.CATEGORY.SUBCATEGORY` | nist.gov/cyberframework | Allowed for cross-walk to other frameworks. |
| **SLSA v1.0** | `SLSA v1.0 Build.L#` / `Source.L#` | slsa.dev | Allowed for supply-chain integrity levels. |
| **CycloneDX 1.5** | `CycloneDX 1.5 §X` | cyclonedx.org/specification/overview | Allowed for SBOM data format. |
| **SPDX 2.3 / 3.0** | `SPDX X.Y` | spdx.dev | Allowed for SBOM and licensing. |
| **CWE** | `CWE-####` | cwe.mitre.org | Allowed for weakness identification. |
| **CAPEC** | `CAPEC-####` | capec.mitre.org | Allowed for attack pattern identification. |
| **CIS Benchmarks** | `CIS Benchmark for <product> vX.Y` | cisecurity.org | Allowed for product-specific hardening references. |
| **OAuth 2.0 / OIDC RFCs** | `RFC ####` | datatracker.ietf.org | Allowed for protocol references. |
| **OpenSSF Scorecard** | `OpenSSF Scorecard check: <name>` | openssf.org | Allowed for open-source security posture. |

### Regulatory frameworks (cited where relevant)

| Source | Citation pattern | Domain | Status |
|---|---|---|---|
| **EU AI Act (Regulation (EU) 2024/1689)** | `EU AI Act Art. ##` | eur-lex.europa.eu | Allowed for AI regulatory references. |
| **GDPR (Regulation (EU) 2016/679)** | `GDPR Art. ##` | eur-lex.europa.eu | Allowed for privacy references. |
| **HIPAA** | `HIPAA Privacy Rule §####` | hhs.gov | Allowed for healthcare references. |
| **PCI DSS v4** | `PCI DSS v4 Req. #.#` | pcisecuritystandards.org | Allowed for payment-data references. |
| **SOX** | `SOX §404` | congress.gov | Allowed for audit / controls references. |

### Vendor product context — allowed citation, NOT a threat-intel source

These vendors and their products may be cited as **product / capability context** only. They MUST NOT be cited as threat-intel sources (no statistics, no breach rates, no claim of "we measured this attack").

| Source | Citation pattern | Allowed use |
|---|---|---|
| **Anthropic Claude Mythos / Project Glasswing** | `Anthropic Claude Mythos (as of YYYY-MM-DD)` | Model capability tier reference. NOT a threat-intel source. |
| **OpenAI capability tier docs** | URL to a dated docs page | Model capability tier reference. NOT a threat-intel source. |
| **GitHub Copilot product docs** | URL to a dated docs page | Product behaviour reference. NOT a threat-intel source. |
| **Cursor product docs** | URL to a dated docs page | Product behaviour reference. NOT a threat-intel source. |
| **MCP specification docs** | URL to modelcontextprotocol.io | Protocol behaviour reference. NOT a threat-intel source. |

### Background context — allowed as context, may not be sole citation

| Source | Status |
|---|---|
| **CSA briefings (Mythos-Ready Security Program and similar)** | Allowed as background framing only. Mythos pillar set in this library is cross-referenced to OWASP / NIST / ISO so claims survive CSA revisions. CSA-only citations MUST be paired with at least one entry from the **Standards** section. |
| **Academic security papers** | Allowed as a secondary citation alongside a primary-source dated standard or threat-intel report. |
| **Conference talks (Black Hat, DEF CON, RSA, etc.)** | Allowed only when the talk's slides or paper are publicly available at a stable URL with a date; pair with at least one **Standards** or **Threat-intel** entry. |

### Framework and tool security documentation (primary vendor / community docs)

These are authoritative security guides published by framework maintainers or the OWASP Cheat Sheet Series. They may be cited as primary references for framework-specific secure-defaults. They MUST NOT be used as threat-intelligence sources for numeric statistics.

| Source | Citation pattern | Domain | Status |
|---|---|---|---|
| **OWASP AI Security and Privacy Guide (AI Exchange)** | URL to owaspai.org | owaspai.org | Allowed; OWASP-published AI security guidance. Pair with NIST AI RMF or ISO 42001 for normative claims. |
| **Angular Security Guide** | URL to angular.dev/best-practices/security | angular.dev | Allowed; official Angular framework security documentation. |
| **Vue.js Security Guide** | URL to vuejs.org/guide/best-practices/security.html | vuejs.org | Allowed; official Vue.js framework security documentation. |
| **Svelte / SvelteKit Security** | URL to kit.svelte.dev or svelte.dev | svelte.dev / kit.svelte.dev | Allowed; official Svelte framework documentation. |
| **Django Security Guide** | URL to docs.djangoproject.com/.../topics/security/ | docs.djangoproject.com | Allowed; official Django security topic guide. |
| **Flask Security Guide** | URL to flask.palletsprojects.com/.../security/ | flask.palletsprojects.com | Allowed; official Flask security documentation. |
| **FastAPI Security** | URL to fastapi.tiangolo.com/tutorial/security/ | fastapi.tiangolo.com | Allowed; official FastAPI security tutorial. |
| **Express.js Security Best Practices** | URL to expressjs.com/en/advanced/best-practice-security.html | expressjs.com | Allowed; official Express.js security guide. |
| **Spring Security Reference** | URL to docs.spring.io/spring-security/reference/ | docs.spring.io | Allowed; official Spring Security documentation. |
| **ASP.NET Core Security** | URL to learn.microsoft.com/en-us/aspnet/core/security/ | learn.microsoft.com | Allowed; official Microsoft ASP.NET Core security documentation. |
| **Ruby on Rails Security Guide** | URL to guides.rubyonrails.org/security.html | guides.rubyonrails.org | Allowed; official Rails security guide. |
| **React Native Security** | URL to reactnative.dev/docs/security | reactnative.dev | Allowed; official React Native security documentation. |
| **LangChain Security** | URL to python.langchain.com/docs/security | python.langchain.com | Allowed; official LangChain security guidance. |
| **in-toto supply-chain framework** | URL to in-toto.io | in-toto.io | Allowed; supply-chain integrity standard reference. |
| **CSA Artificial Intelligence research** | URL to cloudsecurityalliance.org/research/topics/artificial-intelligence | cloudsecurityalliance.org | Allowed as background context only; must be paired with OWASP / NIST / ISO anchors per ADR 0004. |
| **Windsurf / Codeium rules documentation** | URL to docs.codeium.com/windsurf/ | docs.codeium.com | Allowed as vendor product context (product behaviour reference only). |
| **Python bandit SAST** | URL to bandit.readthedocs.io | bandit.readthedocs.io | Allowed; official documentation for the PyCQA bandit static-analysis tool. |
| **Python safety / pip-audit** | URL to pypi.org/project/safety or safety.security | pypi.org / safety.security | Allowed; official documentation for the safety/pip-audit dependency vulnerability scanner. |
| **npm audit** | URL to docs.npmjs.com/cli/commands/npm-audit | docs.npmjs.com | Allowed; official npm CLI documentation for the built-in dependency audit command. |
| **Snyk Open Source** | URL to docs.snyk.io | docs.snyk.io | Allowed as a supplementary tool reference; NOT a primary threat-intel source for numeric statistics. |
| **OWASP Dependency-Check** | URL to owasp.org/www-project-dependency-check/ | owasp.org | Allowed; OWASP-published dependency analysis tool documentation. |
| **govulncheck (Go vulnerability checker)** | URL to pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | pkg.go.dev | Allowed; official Go team vulnerability-scanning tool. |
| **RustSec / cargo-audit** | URL to rustsec.org | rustsec.org | Allowed; official Rust security advisory database and cargo-audit tool. |
| **TypeScript compiler documentation** | URL to typescriptlang.org/tsconfig | typescriptlang.org | Allowed; official TypeScript compiler option reference (strict mode, strictNullChecks, etc.). |
| **.NET code analysis documentation** | URL to learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/ | learn.microsoft.com | Allowed; official Microsoft documentation for .NET Roslyn analyzers and code-analysis rules. |
| **bundler-audit (Ruby SCA)** | URL to github.com/rubysec/bundler-audit | github.com/rubysec | Allowed; official repository and documentation for the Ruby bundler-audit dependency vulnerability scanner. |

## Disallowed (CI will block)

- **Vendor blog posts as the sole source for a numeric threat statistic.** Pair with a Threat-intel report from the allowlist or do not make the claim.
- **Undated assertions** of breach trends, dwell times, attack frequencies, or "X% of incidents involved AI" — even when paraphrasing.
- **"AI experts say…"** without a dated study or named expert with a public publication.
- **Paywalled or confidential sources** without a public restatement.
- **Self-citation to this repository** as a primary source for a threat claim (the library defines controls, not threat statistics).

## How `source-hygiene.yml` enforces this file (Phase 6)

The workflow performs three passes:

1. **Citation extraction.** Regex-scan every `.md`, `.yaml`, and `.json` file for URL patterns, ISO/NIST/MITRE ID patterns, and dated patterns (`(YYYY)`, `as of YYYY-MM-DD`).
2. **Allowlist cross-reference.** Every extracted citation MUST match an entry in this file. Unknown URLs and unknown ID patterns fail the workflow.
3. **Threat-statistic context check.** When a paragraph contains a numeric pattern (`\d{1,3}%`, `\d+ days?`, etc.) and a vendor product name, fail unless the paragraph also references a Threat-intel report.

The workflow also runs the **Mermaid accessibility lint** — every ```mermaid``` block MUST include `accTitle` and `accDescr` directives (Mermaid v10+ syntax).

## How to add a source

1. Open a PR adding the source to the right section above with:
   - A citation pattern.
   - A short justification (1–2 sentences) for why it qualifies.
   - A dated URL.
2. If the source enables a new claim, also update `source-hygiene.yml` regex sets.
3. If the source is supersedence (a new ASVS version, for example), keep the prior entry with a `(superseded YYYY-MM)` note for one MINOR cycle.

## Standards URLs (current, as of 2026-06)

- OWASP ASVS v5: <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 for LLM Applications: <https://genai.owasp.org/llm-top-10/>
- OWASP Cheat Sheet Series: <https://cheatsheetseries.owasp.org/>
- ISO/IEC 27001:2022: <https://www.iso.org/standard/27001>
- ISO/IEC 42001:2023: <https://www.iso.org/standard/81230.html>
- NIST AI RMF 1.0: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI 600-1 (GenAI Profile, 2024): <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- NIST SP 800-218 (SSDF): <https://csrc.nist.gov/publications/detail/sp/800-218/final>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- SLSA v1.0: <https://slsa.dev/>
- CycloneDX 1.5: <https://cyclonedx.org/specification/overview/>
- SPDX: <https://spdx.dev/>
- CWE: <https://cwe.mitre.org/>
- CAPEC: <https://capec.mitre.org/>
- MITRE ATT&CK: <https://attack.mitre.org/>
- MITRE ATLAS: <https://atlas.mitre.org/>
- CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks/>
- EU AI Act: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>
- Verizon DBIR: <https://www.verizon.com/business/resources/reports/dbir/>
- Mandiant M-Trends: <https://cloud.google.com/security/resources/m-trends>
- CrowdStrike Global Threat Report: <https://www.crowdstrike.com/global-threat-report/>
- Microsoft Digital Defense Report: <https://www.microsoft.com/security/blog/digital-defense-report/>
- ENISA Threat Landscape: <https://www.enisa.europa.eu/topics/cyber-threats/threats-and-trends>
- CISA Advisories: <https://www.cisa.gov/news-events/cybersecurity-advisories>
- Google Threat Analysis Group: <https://blog.google/threat-analysis-group/>

## Framework and tool documentation URLs (as of 2026-06)

- OWASP AI Exchange: <https://owaspai.org/>
- CSA AI Safety Initiative: <https://cloudsecurityalliance.org/research/topics/artificial-intelligence>
- Angular Security Guide: <https://angular.dev/best-practices/security>
- OWASP Angular Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Angular_Based_Application_Security_Cheat_Sheet.html>
- Vue.js Security Guide: <https://vuejs.org/guide/best-practices/security.html>
- SvelteKit Documentation: <https://kit.svelte.dev/docs/introduction>
- Django Security Guide: <https://docs.djangoproject.com/en/stable/topics/security/>
- Flask Security Guide: <https://flask.palletsprojects.com/en/latest/security/>
- FastAPI Security: <https://fastapi.tiangolo.com/tutorial/security/>
- Express.js Security Best Practices: <https://expressjs.com/en/advanced/best-practice-security.html>
- Spring Security Reference: <https://docs.spring.io/spring-security/reference/>
- ASP.NET Core Security: <https://learn.microsoft.com/en-us/aspnet/core/security/>
- Ruby on Rails Security Guide: <https://guides.rubyonrails.org/security.html>
- React Native Security: <https://reactnative.dev/docs/security>
- LangChain Security: <https://python.langchain.com/docs/security>
- in-toto: <https://in-toto.io/>
- Windsurf Rules Docs: <https://docs.codeium.com/windsurf/>
- Python bandit: <https://bandit.readthedocs.io/>
- Python safety: <https://safety.security/>
- npm audit: <https://docs.npmjs.com/cli/commands/npm-audit>
- Snyk: <https://docs.snyk.io/>
- OWASP Dependency-Check: <https://owasp.org/www-project-dependency-check/>
- govulncheck: <https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck>
- RustSec / cargo-audit: <https://rustsec.org/>
- TypeScript compiler (tsconfig reference): <https://www.typescriptlang.org/tsconfig/>
- .NET code analysis: <https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview>
- bundler-audit (Ruby): <https://github.com/rubysec/bundler-audit>

## Convention and tooling references (v1 preserved content)

These domains appear in pre-existing v1 prompt files and guidelines that are preserved unmodified.
They are authoritative secondary references for their respective topics and may be cited as guidance
sources alongside primary standards from the allowlist above.

| Source | Domain | Status |
|---|---|---|
| **Keep a Changelog** | keepachangelog.com | Changelog convention reference. |
| **Semantic Versioning** | semver.org | Versioning convention reference. |
| **AGENTS.md community standard** | agents.md | Agentic IDE instruction format reference. |
| **pre-commit framework** | pre-commit.com | Pre-commit hook framework documentation. |
| **JSON Schema Store (SARIF)** | json.schemastore.org | Machine-readable schema registry; cited in SARIF output examples. |
| **Shields.io** | img.shields.io | Badge image service; used for README status badges only. |
| **GitHub Documentation** | docs.github.com | Official GitHub platform documentation. |
| **GitHub Security Lab** | securitylab.github.com | GitHub's security research publications. |
| **Cursor IDE Documentation** | docs.cursor.com | Official Cursor IDE documentation. |
| **Anthropic Documentation** | docs.anthropic.com | Official Anthropic developer documentation. |
| **AWS Documentation** | docs.aws.amazon.com | Official Amazon Web Services documentation. |
| **AWS Architecture Center** | aws.amazon.com | Official AWS architecture and security guidance. |
| **Android Security** | source.android.com | Official Android Open Source Project security documentation. |
| **Android Developer Docs** | developer.android.com | Official Android developer documentation. |
| **Apple Developer Documentation** | developer.apple.com | Official Apple developer documentation. |
| **Apple Security Guide** | support.apple.com | Official Apple platform security guide. |
| **Docker Documentation** | docs.docker.com | Official Docker container platform documentation. |
| **Pydantic Documentation** | docs.pydantic.dev | Official Pydantic data validation library documentation. |
| **SQLAlchemy Documentation** | docs.sqlalchemy.org | Official SQLAlchemy ORM documentation. |
| **Next.js Documentation** | nextjs.org | Official Next.js framework documentation. |
| **NextAuth.js Documentation** | next-auth.js.org | Official NextAuth.js authentication library documentation. |
| **Microsoft Documentation (legacy)** | docs.microsoft.com | Microsoft documentation (legacy domain; newer docs at learn.microsoft.com). |
| **Terraform Documentation** | www.terraform.io | Official HashiCorp Terraform documentation. |
| **Terraform Registry** | registry.terraform.io | Official Terraform provider and module registry. |
| **Checkov IaC Scanner** | checkov.io | Official Checkov infrastructure-as-code scanning documentation. |
| **Google AI Responsibility** | ai.google | Google AI principles and responsibility documentation. |
| **AI Incident Database** | incidentdatabase.ai | Partnership on AI incident database; secondary reference for AI governance context. |
| **Cryptography Coding Rules** | cryptocoding.net | Community-maintained cryptography implementation rules. |
| **Node.js Security** | nodejs.org | Official Node.js security guides and documentation. |
| **NIST Publications** | pages.nist.gov | NIST Special Publications (SP 800-63 etc.); supplement to nist.gov primary. |
| **Auth0 Documentation** | auth0.com | Okta/Auth0 developer documentation; secondary implementation reference. |
| **LogRocket Blog** | blog.logrocket.com | Tech blog; secondary reference for framework implementation examples. |
| **Threat Modeling Manifesto** | www.threatmodelingmanifesto.org | Community threat modeling principles document. |
| **Versprite PASTA Research** | versprite.com | PASTA threat modeling methodology research. |
| **Security Compass** | securitycompass.com | Security methodology and PASTA publications. |
| **Security Headers** | securityheaders.com | HTTP security headers scanner and reference tool. |
| **OWASP MAS / MASVS** | mas.owasp.org | OWASP Mobile Application Security Verification Standard. |

### Documentation URLs (as of 2026-06)

- Keep a Changelog: <https://keepachangelog.com/en/1.1.0/>
- Semantic Versioning: <https://semver.org/spec/v2.0.0.html>
- AGENTS.md: <https://agents.md/>
- pre-commit framework: <https://pre-commit.com/>
- JSON Schema Store: <https://json.schemastore.org/>
- GitHub Documentation: <https://docs.github.com/>
- GitHub Security Lab: <https://securitylab.github.com/>
- Cursor Documentation: <https://docs.cursor.com/>
- Anthropic Documentation: <https://docs.anthropic.com/>
- AWS Documentation: <https://docs.aws.amazon.com/>
- AWS Architecture Center: <https://aws.amazon.com/architecture/security-identity-compliance/>
- Android Security: <https://source.android.com/security>
- Android Developer: <https://developer.android.com/topic/security/best-practices>
- Apple Developer: <https://developer.apple.com/documentation/security>
- Apple Security Guide: <https://support.apple.com/guide/security/welcome/web>
- Docker Documentation: <https://docs.docker.com/engine/security/>
- Pydantic: <https://docs.pydantic.dev/latest/>
- SQLAlchemy: <https://docs.sqlalchemy.org/en/20/>
- Next.js: <https://nextjs.org/docs/advanced-features/security-headers>
- NextAuth.js: <https://next-auth.js.org/configuration/options>
- Terraform: <https://www.terraform.io/docs/>
- Terraform Registry: <https://registry.terraform.io/>
- Checkov: <https://www.checkov.io/>
- Google AI: <https://ai.google/responsibilities/responsible-ai-practices/>
- AI Incident Database: <https://incidentdatabase.ai/>
- Cryptography Coding Rules: <https://cryptocoding.net/index.php/Coding_rules>
- Node.js Security: <https://nodejs.org/en/docs/guides/security/>
- NIST SP 800-63-3: <https://pages.nist.gov/800-63-3/sp800-63b.html>
- Auth0: <https://auth0.com/>
- LogRocket Blog: <https://blog.logrocket.com/>
- Threat Modeling Manifesto: <https://www.threatmodelingmanifesto.org/>
- Versprite PASTA: <https://versprite.com/blog/what-is-pasta-threat-modeling/>
- Security Compass PASTA: <https://www.securitycompass.com/blog/application-threat-modeling-the-pasta-way/>
- Security Headers: <https://securityheaders.com/>
- OWASP MASVS: <https://mas.owasp.org/>
