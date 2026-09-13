GO ?= go
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
BIN_DIR ?= bin

SANDCASTLE_BIN := $(BIN_DIR)/sandcastle
SC_ALIAS := $(BIN_DIR)/sc
SANDCASTLE_ADMIN_BIN := $(BIN_DIR)/sandcastle-admin
SC_ADM_ALIAS := $(BIN_DIR)/sc-adm

.PHONY: build install test e2e-safe clean skill-sync

# The Sandcastle agent skill is tracked at docs/agents/skills/sandcastle and
# embedded into the binary from internal/agentskill/sandcastle (go:embed
# cannot reach outside its package). Run this after editing the tracked
# directory; TestEmbeddedSkillMatchesTrackedSource fails on any drift.
SKILL_SRC := docs/agents/skills/sandcastle
SKILL_EMBED := internal/agentskill/sandcastle
skill-sync:
	rm -rf $(SKILL_EMBED)
	mkdir -p $(dir $(SKILL_EMBED))
	cp -R $(SKILL_SRC) $(SKILL_EMBED)

# One fat binary; the other names are symlinks that select their role via argv[0]
# (see cmd/sandcastle/main.go). No separate admin binary is built.
build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(SANDCASTLE_BIN) ./cmd/sandcastle
	ln -sf sandcastle $(SC_ALIAS)
	ln -sf sandcastle $(SANDCASTLE_ADMIN_BIN)
	ln -sf sandcastle $(SC_ADM_ALIAS)

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(SANDCASTLE_BIN) $(DESTDIR)$(BINDIR)/sandcastle
	ln -sf sandcastle $(DESTDIR)$(BINDIR)/sc
	ln -sf sandcastle $(DESTDIR)$(BINDIR)/sandcastle-admin
	ln -sf sandcastle $(DESTDIR)$(BINDIR)/sc-adm

test:
	$(GO) test ./...

# unit + gated + Phase 12 (Public DNS Zones). Phase 12 runs only when
# SANDCASTLE_E2E=1 and .env.sc2 (or the env) carries
# SANDCASTLE_E2E_CLOUDFLARE_TOKEN + SANDCASTLE_E2E_PUBLIC_DNS_ZONE; otherwise
# it is skipped, not failed.
e2e-safe:
	scripts/e2e.sh unit
	scripts/e2e.sh gated
	scripts/e2e.sh pdz


clean:
	rm -rf $(BIN_DIR)
