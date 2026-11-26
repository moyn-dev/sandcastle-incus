ARG SANDCASTLE_BASE_IMAGE=sandcastle/base:latest
FROM ${SANDCASTLE_BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# Toolchain layer: independent of the pinned tool versions, so it stays cached
# across version bumps. The apt cache mounts keep downloaded .debs and package
# lists on the builder's cache volume (not in the image layer), so even when this
# layer is invalidated by a base-image change the install runs from local cache
# instead of re-fetching ~150 MB. docker-clean is removed so apt keeps archives.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        gh \
        python3 \
        python3-pip

# Node.js through mise (in the base image), not Debian's nodejs: Debian 13
# ships Node 20, and current Claude Code and the skills installer need >= 22.
# Installed system-wide under /usr/local/share/mise (not a user's ~/.local),
# node/npm/npx linked into /usr/local/bin so every login shell finds them,
# and npm's global prefix is /usr/local so `npm install -g` lands there too.
ARG NODE_VERSION=22
RUN MISE_DATA_DIR=/usr/local/share/mise mise install "node@${NODE_VERSION}" \
    && node_bin="$(MISE_DATA_DIR=/usr/local/share/mise mise where "node@${NODE_VERSION}")/bin" \
    && for tool in node npm npx; do ln -sf "$node_bin/$tool" "/usr/local/bin/$tool"; done \
    && npm config set prefix /usr/local --location=global \
    && node --version && npm --version

# Tool-version args are declared here (after the toolchain layer) so a version
# bump rebuilds only the npm layer below, not the apt layer above.
ARG CODEX_CLI_VERSION
ARG CLAUDE_CODE_VERSION
ARG GEMINI_CLI_VERSION
RUN test -n "${CODEX_CLI_VERSION}" \
    && test -n "${CLAUDE_CODE_VERSION}" \
    && test -n "${GEMINI_CLI_VERSION}"

# Shared with images/dev/Dockerfile (images/dev/install-ai-cli-tools.sh is a
# byte-identical copy of this script, enforced by
# images/dev/install_ai_cli_tools_test.go) so the two templates never drift
# on how the AI CLI toolchain / skills bundle gets installed.
COPY install-ai-cli-tools.sh /usr/local/sbin/install-ai-cli-tools.sh
RUN chmod 0755 /usr/local/sbin/install-ai-cli-tools.sh

RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    /usr/local/sbin/install-ai-cli-tools.sh cli \
        "${CODEX_CLI_VERSION}" "${CLAUDE_CODE_VERSION}" "${GEMINI_CLI_VERSION}"

# Install Matt Pocock's agent skills into /etc/skel so every tenant user created
# by `useradd --create-home` (see sandcastle-bootstrap) inherits them under
# ~/.claude/skills. HOME drives the `-g` (global) install target. SKILLS_VERSION
# pins the installer for reproducibility; bump it deliberately to refresh skills.
ARG SKILLS_VERSION=latest
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    install -d /etc/skel \
    && HOME=/etc/skel /usr/local/sbin/install-ai-cli-tools.sh skills "${SKILLS_VERSION}"

ARG SANDCASTLE_IMAGE_TEMPLATE=ai
ARG SANDCASTLE_IMAGE_TAG=sandcastle/ai:latest
ARG SANDCASTLE_IMAGE_VERSION=unknown
ARG SANDCASTLE_IMAGE_COMMIT_DATE=unknown
RUN printf 'Sandcastle %s image\nVersion: %s\nImage: %s\nLast commit: %s\n\n' \
        "$SANDCASTLE_IMAGE_TEMPLATE" \
        "$SANDCASTLE_IMAGE_VERSION" \
        "$SANDCASTLE_IMAGE_TAG" \
        "$SANDCASTLE_IMAGE_COMMIT_DATE" \
        >/etc/issue \
    && cp /etc/issue /etc/issue.net

WORKDIR /workspace
CMD ["sleep", "infinity"]
