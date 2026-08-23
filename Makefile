# Thin wrappers over the docker compose workflow. The compose file remains the
# source of truth; this exists so the everyday cycle is one word each, and so
# the whole emulator family is driven the same way. Nothing here is required —
# every target shows the command it runs.
#
#   make up      # start the pair (entra-emulator + keyvault-emulator)
#   make status  # is the pair actually usable? (exit non-zero if not)
#   make down    # stop and remove the containers
#
# Linux, macOS and Windows. On Windows the recipes run under a POSIX shell —
# `sh.exe` from Git for Windows, which also supplies the grep/awk/curl the
# scripts use. Install once and everything below works from PowerShell or cmd:
#
#   winget install Git.Git         # provides sh.exe + grep/awk/cut/curl
#   winget install ezwinports.make # GNU Make itself (no admin needed)
#
# `make doctor` checks the whole toolchain and prints what is missing.
#
# The default is the PAIR — entra issues the tokens, this vault validates them.
# Add the third member (fabric-emulator, for the secret-as-SP-credential chain)
# with the profile the compose file gates it behind:
#
#   make up PROFILE="--profile full"
#
# ARM governs authorization by default, as in Azure: role assignments and the
# vault resource decide access, and the stack seeds the grant Azure would give
# the principal that created the vault. NOARM=1 opts out, handing authorization
# back to the emulator's own /_emulator control surface.
#
#   make up
#   make up NOARM=1
NOARM   ?=
ifeq ($(NOARM),1)
  COMPOSE_ENV = KV_ARM_URL=
else
  COMPOSE_ENV =
endif
COMPOSE  = $(COMPOSE_ENV) docker compose $(PROFILE)

# Windows: force the recipes onto sh.exe. GNU Make on Windows falls back to
# cmd.exe when it cannot find a shell, and cmd cannot run a single line of what
# is below. Make searches PATH for this itself, so the spaces in
# "C:\Program Files\Git\bin" are its problem, not ours.
ifeq ($(OS),Windows_NT)
  SHELL := sh.exe
  .SHELLFLAGS := -c
endif

# Which interpreter is "python3" is not a given. On Windows `python3` normally
# resolves to the Microsoft Store *alias stub*: it exists on PATH, so
# `command -v python3` succeeds, and then it exits 49 with a "not found, install
# from the Store" message. Detection therefore has to RUN each candidate, not
# merely locate it. Override with PY= if you keep python somewhere unusual.
PY ?= $(shell for c in python3 python py; do if "$$c" -c '' >/dev/null 2>&1; then echo "$$c"; break; fi; done)

.PHONY: help doctor up down restart clean status logs ps test chain docs-build docs-serve

help: ## Show the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

doctor: ## Check the toolchain and the docker context this Makefile needs
	@sh scripts/doctor.sh

up: ## Start the stack in the background (NOARM=1 drops ARM governance; PROFILE="--profile full" adds fabric)
	$(COMPOSE) up -d

down: ## Stop and remove containers
	$(COMPOSE) down

clean: ## Stop and remove containers AND any anonymous volumes (full reset)
	$(COMPOSE) down -v

restart: clean up ## Full reset: clean, then start again

status: ## Report whether the pair is usable (non-zero exit if not)
	@sh scripts/status.sh

ps: ## Container states for this project
	$(COMPOSE) ps

logs: ## Tail logs (SVC=<service> to narrow)
	$(COMPOSE) logs -f --tail 100 $(SVC)

test: ## Go build, vet and unit tests (starts a real entra-emulator in-process)
	go build ./... && go vet ./... && go test ./...

chain: ## The three-emulator secret-as-SP-credential chain (e2e/chain)
	@test -n "$(PY)" || { echo "no working python found (tried python3, python, py); set PY=" >&2; exit 1; }
	$(PY) e2e/chain/run.py

e2e-host-routed: ## Real SDK at {name}.vault.azure.net with TLS + challenge checks ON
	@command -v docker >/dev/null || { echo "docker is required on PATH" >&2; exit 1; }
	python3 e2e/host-routed/run.py

# ---------------------------------------------------------------------------
# The documentation site.
#
# Not called `docs`: there is a docs/ DIRECTORY here, and a target sharing its
# name is satisfied by the directory existing. `make docs` would print
# "nothing to be done" and exit 0, which is the failure that looks like
# success. .PHONY below would also fix it; a name that cannot collide fixes it
# whether or not someone remembers .PHONY.
#
# `pnpm --filter $(DOCS_PKG) dev` is the fast inner loop for PROSE, and it is
# not this. It is based at the docs subpath and knows nothing about the tree
# around it, so under it the landing page does not exist, the redirect stubs do
# not exist, and the badge endpoints the landing page fetches do not exist. Use
# it to write a page; use `make docs-serve` before believing the site works.
#
# CI runs `make docs-build` and publishes exactly what it leaves in ./_site, so
# the thing previewed here is the thing that deploys.
DOCS_PKG  ?= azure-keyvault-emulator-docs
DOCS_PORT ?= 8099
# The go coverage badge needs a full `go test ./...`. It is part of the site,
# so it is part of this target; pass GO_COVERAGE=skip when you are editing
# prose and can live with one badge missing from the preview.
GO_COVERAGE ?= measure
# The interpreter CI uses, pinned. These scripts are stdlib-only, hence
# --no-project: no environment to resolve, and a local 3.9 cannot pass
# something 3.12 would reject.
UVPY ?= uv run --no-project --python 3.12 python

docs-build: ## Build the published site into ./_site (what CI deploys)
	@command -v uv >/dev/null 2>&1 || { echo "uv is not on PATH: https://docs.astral.sh/uv/" >&2; exit 1; }
	pnpm install --frozen-lockfile
	$(UVPY) scripts/check_docs_links.py --strict
	pnpm --filter $(DOCS_PKG) build
	$(UVPY) scripts/assemble_site.py --self-test
	$(UVPY) scripts/assemble_site.py --out _site
	@# AFTER the assembler, which clears _site before it writes.
	@if [ "$(GO_COVERAGE)" = "skip" ]; then \
	  echo "GO_COVERAGE=skip: ./_site will be missing the go coverage badge"; \
	else \
	  go test -coverpkg=./... -coverprofile=cover.out ./... >/dev/null && \
	  pct=$$(go tool cover -func=cover.out | tail -1 | awk '{print $$3}' | tr -d '%') && \
	  echo "go coverage: $${pct}%" && \
	  $(UVPY) scripts/coverage_badges.py --out _site --go "$$pct"; \
	fi
	$(UVPY) scripts/build_landing_data.py --out _site --site _site

docs-serve: docs-build ## …and serve it locally at its published URLs (DOCS_PORT=8099)
	$(UVPY) scripts/assemble_site.py --serve --site _site --port $(DOCS_PORT)
