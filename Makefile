# Secure AI Code Library — Makefile
#
# Local development targets for the canonical YAML registry, JSON Schemas, SBOM,
# documentation site, and CI lints.

SHELL := /bin/sh
.DEFAULT_GOAL := all

REGISTRY_DIR     := registry
RULES_GLOB       := $(REGISTRY_DIR)/rules/**/*.rule.yaml
SUBAGENT_GLOB    := $(REGISTRY_DIR)/subagents/*/subagent.yaml
SPEC_GLOB        := $(REGISTRY_DIR)/framework-specs/*.spec.yaml
SCHEMA_DIR       := $(REGISTRY_DIR)/schemas
INDEX_FILE       := $(REGISTRY_DIR)/INDEX.md
SBOM_FILE        := sbom.cdx.json
SEARCH_INDEX     := js/search-index.json

.PHONY: validate index sbom search-index source-hygiene token-budget dogfood site all help clean

help:
	@echo "Secure AI Code Library — make targets:"
	@echo "  validate       JSON-Schema-validate every file under $(REGISTRY_DIR)/"
	@echo "  index          Regenerate $(INDEX_FILE) from rule summaries"
	@echo "  search-index   Regenerate $(SEARCH_INDEX) for Lunr-based site search"
	@echo "  sbom           Regenerate $(SBOM_FILE) (CycloneDX 1.5) via syft"
	@echo "  source-hygiene Lint citations against docs/SOURCES.md allowlist"
	@echo "  token-budget   tiktoken-count summaries + subagent prompts; warn at 80%"
	@echo "  dogfood        Run hooks/pre-commit.sh against this repo"
	@echo "  site           Local Jekyll preview of the docs site"
	@echo "  all            validate + index + sbom + source-hygiene + token-budget"

validate:
	@bash scripts/validate.sh

index:
	@bash scripts/build-index.sh

sbom:
	@bash scripts/build-sbom.sh

search-index:
	@bash scripts/build-search-index.sh

source-hygiene:
	@bash scripts/source-hygiene-lint.sh

token-budget:
	@bash scripts/token-budget-lint.sh

dogfood:
	@bash hooks/pre-commit.sh --all

site: index sbom search-index
	@echo "Site artifacts regenerated. Jekyll/GitHub Pages picks them up on push."

all: validate index sbom search-index source-hygiene token-budget
	@echo "All checks passed."

clean:
	@echo "==> make clean"
	@# Auto-generated artefacts only; do not touch hand-authored content.
	@# rm -f $(INDEX_FILE) $(SEARCH_INDEX) $(SBOM_FILE)
	@echo "    (no-op in Phase 1; targets regenerate on demand)"
