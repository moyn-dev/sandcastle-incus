# GitHub release checking & self-update — primary-source research

**Date:** 2026-07-17
**Question:** What is the factually correct way for the `sandcastle` CLI to do a ~daily unauthenticated "is there a newer release?" check against GitHub, verify downloads, and (optionally) self-update — grounded in GitHub API docs, GoReleaser docs, this repo's real release artifacts, and prior art (minio/selfupdate, creativeprojects/go-selfupdate, gh, flyctl)?

All claims cite a URL or file path. Live-API observations were made 2026-07-17 against the real `moyn-dev/sandcastle-incus` v0.1.0 release.

---

## 1. GitHub releases API for an unauthenticated daily check

### Rate limits

- **Primary unauthenticated limit: 60 requests/hour, keyed by originating IP.** The docs state: *"The primary rate limit for unauthenticated requests is 60 requests per hour"*, and that unauthenticated limits are *"associated with the originating IP address"* — [docs.github.com — Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
- **Secondary limits** (same doc) that could theoretically apply: no more than 100 concurrent requests; ≤900 REST "points" per minute; ≤90 s CPU per 60 s real time. None are remotely relevant to one request per day per client, but *"Continuing to make requests while you are rate limited may result in the banning of your integration"* — [Best practices for using the REST API](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).
- Rate-limit state is reported in response headers `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-used`, `x-ratelimit-reset`, `x-ratelimit-resource` ([rate-limit docs](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)). Observed live unauthenticated against this repo: `x-ratelimit-limit: 60`, `x-ratelimit-resource: core`.

### Best endpoint: `GET /repos/{owner}/{repo}/releases/latest`

- Doc wording ([Releases REST reference](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#get-the-latest-release)): *"The latest release is the most recent non-prerelease, non-draft release, sorted by the `created_at` attribute. The `created_at` attribute is the date of the commit used for the release, and not the date when the release was drafted or published."*
- This is exactly the right semantic for an update check (drafts and prereleases are excluded automatically), and it is **one** request. Listing `/releases` or `/tags` returns pages you'd have to sort/filter yourself and includes drafts/prereleases (releases list) or every tag (tags list) — strictly worse for this use.
- For a **pinned** version, use `GET /repos/{owner}/{repo}/releases/tags/{tag}` (same response schema) — [same doc page](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#get-a-release-by-tag-name).
- Works unauthenticated for public repos (release information *"is available to everyone"* per the doc's fine-grained-token note; confirmed live below).

### Conditional requests (ETag / 304) — the critical nuance

- Docs ([Best practices — use conditional requests if appropriate](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)): *"Making a conditional request does not count against your primary rate limit if a `304` response is returned **and the request was made while correctly authorized with an `Authorization` header**."* (emphasis added)
- **So the "304 is free" exemption is documented for authenticated requests only.** Verified empirically, unauthenticated, against this repo on 2026-07-17:
  1. `GET /repos/moyn-dev/sandcastle-incus/releases/latest` → `200`, `etag: W/"ca0d7a92…"`, `x-ratelimit-used: 2`
  2. Same request with `If-None-Match: W/"ca0d7a92…"` → **`HTTP/2 304`**, but `x-ratelimit-used: 3` — **the unauthenticated 304 still consumed a request.**
- Conclusion: for an unauthenticated daily check, the ETag saves **bandwidth** (empty body on 304) but not **quota**. That's fine — 1 request/day against 60/hour/IP is negligible. Still send `If-None-Match` (store the last ETag next to the cached result): a 304 is a cheap, definitive "nothing changed" signal and skips JSON parsing.
- Caveat observed live: the ETag varies with the request's `Accept` header (different representation → different ETag), so always send the **same** headers when replaying it.
- GitHub's general polling guidance is "use webhooks instead" ([best-practices doc](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)) — not applicable to a CLI on end-user machines; a daily poll is the accepted pattern (see gh/flyctl below).

### Headers and response shape

- Recommended request headers ([Releases reference](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28)): `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: <version>`. Supported versions as of 2026-07-17 (live `gh api /versions`): `["2026-03-10", "2022-11-28"]`. No `Authorization` header is needed for public releases (confirmed live: unauthenticated `curl` returns 200 + full JSON).
- The Release JSON includes `tag_name` (e.g. `"v0.1.0"`) and `assets[]`, each asset carrying `name`, `size`, `content_type`, and `browser_download_url` ([release object schema in the same doc](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#get-the-latest-release); confirmed in the live response for this repo, §2).
- Also live-observed: the endpoint returns a `last-modified` header, so `If-Modified-Since` is an alternative conditional mechanism ([best-practices doc](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)).

---

## 2. What this repo actually publishes

Source: [`.goreleaser.yaml`](../../.goreleaser.yaml) and live `gh release view --repo moyn-dev/sandcastle-incus --json tagName,assets` (latest = `v0.1.0`, 2026-07-15).

### Name template → concrete names

`.goreleaser.yaml` lines 40–46:

```yaml
archives:
  - formats: [tar.gz]
    name_template: sandcastle-{{ .Os }}-{{ .Arch }}
checksum:
  name_template: checksums.txt
  algorithm: sha256
```

with `goos: [linux, darwin]`, `goarch: [amd64, arm64]` (lines 29–34). Real assets on `v0.1.0` (from `gh release view`):

| Asset | Size | Content type |
|---|---|---|
| `sandcastle-darwin-amd64.tar.gz` | 8,399,710 | application/gzip |
| `sandcastle-darwin-arm64.tar.gz` | 7,883,742 | application/gzip |
| `sandcastle-linux-amd64.tar.gz` | 9,365,355 | application/gzip |
| `sandcastle-linux-arm64.tar.gz` | 8,599,713 | application/gzip |
| `checksums.txt` | 386 | text/plain; charset=utf-8 |

So the deterministic client-side rule is: **asset name = `sandcastle-${GOOS}-${GOARCH}.tar.gz`** — `runtime.GOOS`/`runtime.GOARCH` map 1:1 to GoReleaser's default `{{ .Os }}`/`{{ .Arch }}` values for these four targets. Each tarball contains the single `sandcastle` binary (build id/binary `sandcastle`, lines 21–24).

`checksums.txt` is standard `sha256sum` format (fetched live from the v0.1.0 release):

```
8b634263cd39e4582f997ff5309576b64bb50f3afff58c1abe07ad93396a6606  sandcastle-darwin-amd64.tar.gz
addeea30c61da3b75356441b72b361d01303389e651adff5cbe67b1322543418  sandcastle-darwin-arm64.tar.gz
0c47c95fe30ce68f8edc5790bf6a54d7a0ac2b2255620aacc601c9d993797830  sandcastle-linux-amd64.tar.gz
c7747b587d52e3b2e966d2f2d449e4557e07b3a4492a1aaa4afb1f55705886f1  sandcastle-linux-arm64.tar.gz
```

### Resolving "latest" vs a pinned tag

- **Latest:** `GET https://api.github.com/repos/moyn-dev/sandcastle-incus/releases/latest` → read `tag_name` → pick `assets[]` entry whose `name == "sandcastle-"+GOOS+"-"+GOARCH+".tar.gz"` → download its `browser_download_url`.
- **Pinned:** `GET /repos/moyn-dev/sandcastle-incus/releases/tags/{tag}` ([doc](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#get-a-release-by-tag-name)), same asset-matching step.
- **No-API construction:** download URLs are stable and predictable — `https://github.com/OWNER/REPO/releases/download/TAG/ASSET`. Confirmed live: every asset's `url` in the `gh release view` output is exactly `https://github.com/moyn-dev/sandcastle-incus/releases/download/v0.1.0/<asset>`. Once `tag_name` is known (one API call), all downloads (tarball + `checksums.txt`) can bypass the API entirely — release-asset downloads from `github.com/...` are not REST API calls and don't touch the 60/hr core limit.
- Version comparison: the tag is `v`-prefixed semver (`git tag -a vX.Y.Z`, [CLAUDE.md "Cutting a Homebrew release"](../../CLAUDE.md)); the running binary's version is stamped into `internal/cli.version` via ldflags (`.goreleaser.yaml` line 38), so compare `strings.TrimPrefix(tag_name, "v")` semver-wise against that var. Snapshot/dev builds (`goreleaser --snapshot`, or `make build` without ldflags) won't carry a release version and should skip the check or never report "newer".

---

## 3. Integrity beyond checksums.txt

### What GoReleaser can sign

- The [`signs` section](https://goreleaser.com/customization/sign/) runs an arbitrary command per artifact. Defaults: `cmd: gpg`, `args: ["--output", "${signature}", "--detach-sign", "${artifact}"]`, `signature: ${artifact}.sig`, `artifacts: none` (must be enabled explicitly). Signable artifact classes: `checksum` (the docs' recommended target), `all`, `archive`, `package`, `installer`, `source`, `sbom`, `binary`.
- Cosign is explicitly documented on the same page, including keyless mode producing a `.sigstore.json` bundle (*"combines the certificate and signature into a single `.sigstore.json` file"*) verifiable with `cosign verify-blob` — [goreleaser.com/customization/sign/](https://goreleaser.com/customization/sign/).
- Minisign works as just another `cmd` (the section accepts any command that writes a signature file) — [same page](https://goreleaser.com/customization/sign/).
- [`binary_signs`](https://goreleaser.com/customization/binary_sign/) is the same pipe restricted to individual binaries and run during the build phase — per the docs, *"the only difference is the artifact filtering and that this pipe also runs in the build phase"*.

### This repo today

- **`.goreleaser.yaml` has no `signs` or `binary_signs` section** — verified by reading [.goreleaser.yaml](../../.goreleaser.yaml) end to end (sections present: `release`, `builds`, `archives`, `checksum`, `notarize`, `homebrew_casks`, `changelog`). The only signing is the **conditional macOS codesign+notarization** (lines 52–63), gated on `MACOS_SIGN_P12` being set; and per [CLAUDE.md](../../CLAUDE.md) those secrets may be absent, in which case builds ship unsigned. macOS notarization is an OS-gatekeeper property, not something an updater client verifies cross-platform.

### What client-side verification would cost, per scheme

- **Cosign keyless (sigstore):** verification means checking the certificate chain to Fulcio, the Rekor transparency-log inclusion, and the OIDC identity of the CI run — i.e. embedding the sigstore verification stack ([github.com/sigstore/sigstore-go](https://github.com/sigstore/sigstore-go), or shelling out to `cosign verify-blob` per the [GoReleaser sign docs](https://goreleaser.com/customization/sign/)). That is a large dependency tree (x509/TUF/Rekor/protobuf) for a CLI whose whole point here is a small update check. Strongest guarantees (no long-lived key at all), highest cost.
- **Minisign:** Ed25519 detached signatures; verification needs only [jedisct1/go-minisign](https://github.com/jedisct1/go-minisign) — MIT, 100% Go, essentially two source files (`minisign.go`, `sign.go`) — plus an embedded public key string in the client. Smallest possible footprint; the tradeoff is you must keep the secret key **off CI** for it to add anything (see below).
- **GPG:** Go's `golang.org/x/crypto/openpgp` is formally deprecated: *"Deprecated: this package is unsafe by design, and has numerous known security issues. It is not maintained, and should not be used."* — [pkg.go.dev/golang.org/x/crypto/openpgp](https://pkg.go.dev/golang.org/x/crypto/openpgp). The maintained alternative is the [ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) fork, but for a new design GPG buys nothing over minisign and costs more.

### What checksums.txt does and does not give you

- `checksums.txt` (SHA-256, `.goreleaser.yaml` lines 44–46) fetched over HTTPS from `github.com/moyn-dev/sandcastle-incus/releases/download/...` protects against **corruption, truncation, and CDN/mirror tampering** of the tarball, because the hash list and the tarball are compared against each other.
- It does **not** protect against a compromised GitHub account, tap, or CI pipeline: whoever can publish the release assets publishes the matching `checksums.txt` in the same GoReleaser run (both come out of `.github/workflows/release.yml`). A detached signature only defends against that threat if the signing key lives **outside** the CI that an attacker would compromise — a minisign/GPG key stored as a GitHub Actions secret in the same repo collapses to the same trust domain as the checksums file. Cosign keyless shifts trust to "this artifact was built by *this repo's* Actions workflow", which does defend against a stolen PAT but not a compromised workflow.

### Pragmatic recommendation for a small CLI

Verify the SHA-256 from `checksums.txt` (fetched over HTTPS from the same release) before applying any downloaded binary — this is cheap, dependency-free (`crypto/sha256` + parsing the `sha256sum` format), and matches what [creativeprojects/go-selfupdate](https://github.com/creativeprojects/go-selfupdate) does for GoReleaser projects. Defer signing; if/when wanted, add minisign (tiny signer in CI or offline, [go-minisign](https://github.com/jedisct1/go-minisign) verifier + embedded public key in the client) rather than the sigstore stack.

---

## 4. Prior art in Go self-updaters

### minio/selfupdate — the "apply" primitive

Sources: [README](https://github.com/minio/selfupdate), [apply.go](https://raw.githubusercontent.com/minio/selfupdate/master/apply.go).

- Scope: *"enable your Golang applications to self update"* by applying an update **from an `io.Reader`** — `selfupdate.Apply(resp.Body, selfupdate.Options{})`. It is a fork *"modified for the needs within [the] MinIO project"* of `inconshreveable/go-update`. Apache-2.0. It does **no GitHub API discovery** — the README's own example does a plain `http.Get(url)`; you bring the URL.
- Verification hooks in `Options`: `Checksum` (compared via `verifyChecksum`, hash defaults to SHA-256), `Verifier` for signature schemes, `Patcher` for binary patches ([apply.go](https://raw.githubusercontent.com/minio/selfupdate/master/apply.go)).
- Replace mechanics ([apply.go](https://raw.githubusercontent.com/minio/selfupdate/master/apply.go)): `PrepareAndCheckBinary` writes the verified bytes to a `.%s.new` file in the target dir; `CommitBinary` then (1) removes any stale `.%s.old`, (2) renames the current executable to `.%s.old`, (3) renames `.new` into place; if step 3 fails it renames `.old` back, and `RollbackError()` reports whether that recovery itself failed (*"If no rollback was needed or if the rollback was successful, RollbackError returns nil"*). `OldSavePath` optionally keeps the previous binary.

### creativeprojects/go-selfupdate — the batteries-included solution

Sources: [README](https://github.com/creativeprojects/go-selfupdate), [go.mod](https://raw.githubusercontent.com/creativeprojects/go-selfupdate/main/go.mod).

- Features (README): sources for **GitHub, GitLab, and Gitea**; semver tag detection with arbitrary prefixes (*"Prefix before version number `\d+\.\d+\.\d+` is automatically omitted"*); asset matching by `{cmd}_{goos}_{goarch}{.ext}` naming with ARM-variant fallback (armv7→armv6→armv5→arm) and macOS universal-binary fallback; validation via per-asset `.sha256` files, **unified GoReleaser-style `checksums.txt`**, ECDSA `.sig` signatures, or a custom `Validator` interface; performs the executable replacement with rollback (built on the go-update lineage). MIT.
- Dependency weight ([go.mod](https://raw.githubusercontent.com/creativeprojects/go-selfupdate/main/go.mod)): direct requires include `code.gitea.io/sdk/gitea`, `github.com/google/go-github/v86`, `gitlab.com/gitlab-org/api/client-go`, `github.com/Masterminds/semver/v3`, `github.com/ulikunitz/xz`, `golang.org/x/crypto` — i.e. you pull three forge SDKs to use one. Convenient, but heavy relative to a hand-rolled single-endpoint check.

### gh (cli/cli) — check-and-notify only

Sources: [internal/update/update.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/update/update.go), [internal/ghcmd/cmd.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/ghcmd/cmd.go).

- `CheckForUpdate` hits `repos/{repo}/releases/latest` via `getLatestReleaseInfo()` and **only returns info for a notification — it never self-updates** ([update.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/update/update.go)).
- Throttle: at most once per 24 h — it loads a `StateEntry` (`CheckedForUpdateAt`, `LatestRelease`) from a **`state.yml`** file and skips when `time.Since(stateEntry.CheckedForUpdateAt).Hours() < 24` ([update.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/update/update.go)).
- Opt-outs: `GH_NO_UPDATE_NOTIFIER` env var, running in Codespaces (`CODESPACES`), and non-TTY/CI contexts suppress the check; additionally a **build-time flag** gates it entirely: `if updaterEnabled == "" || !update.ShouldCheckForUpdate() { return nil, nil }` — distro/package builds simply don't set `updaterEnabled` ([update.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/update/update.go), [ghcmd/cmd.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/ghcmd/cmd.go)).
- Version comparison: `versionGreaterThan()` with `hashicorp/go-version`, normalizing git-describe suffixes (`\d+-\d+-g[a-f0-9]{8}$`) into prerelease form ([update.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/update/update.go)).
- Homebrew awareness: `isUnderHomebrew()` in [ghcmd/cmd.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/ghcmd/cmd.go) resolves `brew` with `safeexec.LookPath`, runs `brew --prefix`, and checks whether the gh executable path starts with `{brewPrefix}/bin/`; for brew installs the notification says `To upgrade, run: brew upgrade gh` (and very recent releases <24 h old are not nagged about, giving the bottle time to land).

### flyctl (superfly/flyctl) — background check + real self-update

Source: [internal/update/update.go](https://raw.githubusercontent.com/superfly/flyctl/master/internal/update/update.go).

- Discovery is **not** the GitHub API: `LatestRelease()` queries Fly's own endpoint `https://api.fly.io/app/flyctl_releases/{OS}/{ARCH}/{channel}`, and for brew installs consults `https://formulae.brew.sh/api/formula/flyctl.json` instead.
- The check runs in the background (`BackgroundUpdate()`), with state cached (release validation memoized in-process; the "when did we last check" state lives in flyctl's config/state handling); env vars: `FLY_NO_UPDATE_CHECK` disables, `FLY_UPDATE_CHECK` forces, `CODESPACES` disables.
- It **actually self-updates**, but not by writing bytes itself: `UpgradeInPlace()` re-runs the official installer — `curl -L "https://fly.io/install.sh" | sh` on Unix, the PowerShell install script on Windows (where the old binary must first be renamed with a `.old` suffix), and **`brew upgrade flyctl` when `IsUnderHomebrew()`** — which, like gh, compares the executable path against `brew --prefix`'s bin dir. `Relaunch()` re-executes the new binary.

### Adopt vs hand-roll

- For a **gh-style check-and-notify**, the entire feature is ~100 lines: one GET with `If-None-Match`, a JSON struct with `tag_name`+`assets`, a semver compare, and a small state file. Both gh and flyctl hand-roll exactly this; pulling `creativeprojects/go-selfupdate`'s three forge SDKs for it is not justified.
- For **actual binary replacement**, do not hand-roll the rename dance — use [minio/selfupdate](https://github.com/minio/selfupdate) for the apply step (checksum option + atomic-ish `.new`/`.old` rename with rollback, Windows-safe), feeding it the extracted binary and the SHA-256 from `checksums.txt`.
- **Never self-update a brew-managed binary** — Homebrew owns the file and the next `brew upgrade` would clobber or conflict; both prior arts special-case it (gh: notify `brew upgrade gh`; flyctl: run `brew upgrade flyctl`), detecting brew by executable-path-under-`brew --prefix` ([ghcmd/cmd.go](https://raw.githubusercontent.com/cli/cli/trunk/internal/ghcmd/cmd.go), [flyctl update.go](https://raw.githubusercontent.com/superfly/flyctl/master/internal/update/update.go)).

---

## Recommendation for sandcastle

Concrete, minimal design (phase 1 = notify only, phase 2 = optional `sc upgrade`):

1. **Daily cached check against `releases/latest`.** Once per 24 h (gh's threshold), and only for interactive TTY runs, GET `https://api.github.com/repos/moyn-dev/sandcastle-incus/releases/latest` with `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, and `If-None-Match: <stored etag>`. Persist `{checked_at, etag, latest_tag}` in a small state file under `~/.config/sandcastle/` (gh precedent: `state.yml`). Run it in a goroutine so it never blocks the command (flyctl precedent). A 304 means "no change" — note it still costs 1 of the 60/hr unauthenticated requests (verified empirically; the docs' 304 exemption requires an `Authorization` header), which is irrelevant at 1/day.
2. **Version compare.** `strings.TrimPrefix(tag_name, "v")` vs the ldflags-stamped `internal/cli.version`; skip entirely when the binary carries no release version (dev/snapshot builds) — mirrors gh's `updaterEnabled` build-time gate.
3. **Notify by default; never auto-replace under Homebrew.** Detect brew with the gh/flyctl check (executable path under `brew --prefix`/bin) and print `To upgrade, run: brew upgrade sandcastle` on macOS; otherwise print the release URL or offer `sc upgrade`.
4. **If/when `sc upgrade` is built:** resolve the asset as `sandcastle-{GOOS}-{GOARCH}.tar.gz` from `https://github.com/moyn-dev/sandcastle-incus/releases/download/{tag}/…` (stable URL pattern — no further API calls), download it plus `checksums.txt`, verify SHA-256, extract the `sandcastle` binary, and apply with `minio/selfupdate.Apply` (pass the checksum in `Options`; surface `RollbackError`). Note the symlink layout (`sc`, `sc-adm`, `sandcastle-admin` → one binary, per [CLAUDE.md](../../CLAUDE.md)): replace the symlink **target**, which minio/selfupdate handles since all names resolve to the same file.
5. **Opt-out env var.** Honor something like `SANDCASTLE_NO_UPDATE_NOTIFIER` (gh: `GH_NO_UPDATE_NOTIFIER`; flyctl: `FLY_NO_UPDATE_CHECK`), and also suppress in CI/non-TTY.
6. **Integrity: checksums now, minisign maybe later.** `checksums.txt` SHA-256 over HTTPS covers corruption/CDN tampering; it does not cover a compromised repo/CI (the attacker regenerates it). If that threat ever matters, add a `signs` entry running minisign over `checksums.txt` with an offline key and verify with `jedisct1/go-minisign` + embedded pubkey — skip the sigstore dependency tree. Today `.goreleaser.yaml` has **no** `signs` config, so any client-side signature verification would be aspirational.
