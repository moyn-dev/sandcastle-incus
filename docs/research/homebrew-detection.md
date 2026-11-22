# Research: detecting a Homebrew-managed install and delegating to brew

Resolves [#122](https://github.com/moyn-dev/sandcastle-incus/issues/122), part of the wayfinder map [#116](https://github.com/moyn-dev/sandcastle-incus/issues/116).

Research date: 2026-07-17. All source permalinks pinned to the commits current on that date (cli/cli `2af8c11`, superfly/flyctl `56c828f`, denoland/deno `fe70a4e`, Homebrew/brew `7f45a2a`, thieso2/homebrew-tap `221e365`).

## Summary

- Homebrew's default prefixes are `/opt/homebrew` (Apple Silicon macOS), `/usr/local` (Intel macOS), `/home/linuxbrew/.linuxbrew` (Linux); custom prefixes are possible but explicitly discouraged ("Pick another prefix at your peril!"). Cask payloads live under `$(brew --caskroom)/<token>/<version>/…` and the `binary` stanza symlinks them into `$(brew --prefix)/bin`.
- The two production Go CLIs examined (gh, flyctl) both detect "am I brew-managed?" the same way: `os.Executable()` (or the resolved PATH entry) prefix-compared against `$(brew --prefix)/bin/` obtained by shelling out to `brew --prefix`. Neither greps for `/Caskroom/` or `/Cellar/` — the `bin` symlink prefix check is the prior art. gh explicitly documents why you must keep referring to the *symlink*, not the resolved Cellar path (Homebrew deletes old versioned dirs on upgrade but keeps the symlink).
- `brew upgrade --cask` is unlink/stage/relink, never overwrite-in-place: Homebrew moves the old version's artifacts back to staging, stages the new version into a new `Caskroom/<token>/<new-version>/` dir, recreates the `bin` symlinks with `ln -sfn`, then wipes the old staged copy. A running process keeps its inode per POSIX unlink semantics, so upgrading under a running binary is safe.
- Prior-art spectrum: **gh** never self-replaces — it only prints an update notice, switching the instruction to `brew upgrade gh` when brew-managed. **flyctl** goes furthest: it *executes* `brew upgrade flyctl` via the user's shell from inside `UpgradeInPlace`. **deno** — contrary to the ticket's assumption — has **no** Homebrew/package-manager detection in current `upgrade.rs` at all; it self-replaces unconditionally, with only a root-ownership error that *mentions* package managers.
- This repo's cask (GoReleaser-generated) has two `binary` stanzas (`sandcastle` and `target: "sc"`), per-OS/arch `sha256`+`url`, `livecheck { skip }`, and a macOS `postflight` that strips `com.apple.quarantine` from the staged binary. Any self-replacement that bypasses brew would desynchronize brew's recorded version, be clobbered/reverted by the next `brew upgrade`/`brew reinstall`, and (since the `bin` names are symlinks into the Caskroom) would actually mutate Caskroom contents.

## Detection

### Standard prefixes

- Installer docs: "The script installs Homebrew to its default, supported, best prefix (`/opt/homebrew` for Apple Silicon, `/usr/local` for macOS Intel and `/home/linuxbrew/.linuxbrew` for Linux)" — [docs.brew.sh/Installation](https://docs.brew.sh/Installation).
- `brew --prefix` manpage entry: "Display Homebrew's install path. Default: macOS ARM: `/opt/homebrew`, macOS Intel: `/usr/local`, Linux: `/home/linuxbrew/.linuxbrew`" — [docs.brew.sh/Manpage](https://docs.brew.sh/Manpage).
- Custom prefixes exist but are discouraged: "Do yourself a favour and install to the default prefix so that you can use our pre-built binary packages. Pick another prefix at your peril!" — [docs.brew.sh/FAQ](https://docs.brew.sh/FAQ). Consequence for detection: hard-coding the three default prefixes is *usually* right but not always; asking `brew --prefix` (or reading `$HOMEBREW_PREFIX`, which `brew shellenv` exports along with `$HOMEBREW_CELLAR` — [Manpage](https://docs.brew.sh/Manpage)) is exact.

### Cask layout

- Cask payloads are staged versioned under the Caskroom: the Cask Cookbook's `binary` example sources from `$(brew --caskroom)/operadriver/106.0.5249.119/operadriver_mac64/operadriver`, i.e. `<caskroom>/<token>/<version>/…` — [docs.brew.sh/Cask-Cookbook](https://docs.brew.sh/Cask-Cookbook#stanza-binary). `brew --caskroom` "Display[s] Homebrew's Caskroom path" ([Manpage](https://docs.brew.sh/Manpage)); the formula analog is `--cellar`, "Default: `$(brew --prefix)/Cellar`" (same page). So casks → `Caskroom`, formulae → `Cellar`.
- The `binary` stanza symlinks: "the source file is linked into the `$(brew --prefix)/bin` directory on installation" — [Cask Cookbook, binary stanza](https://docs.brew.sh/Cask-Cookbook#stanza-binary). Confirmed in Homebrew source: `Cask::Artifact::Binary < Symlinked` ([binary.rb](https://github.com/Homebrew/brew/blob/7f45a2a9bad007451e66917011531e5d7d310da5/Library/Homebrew/cask/artifact/binary.rb)), and `Symlinked#create_filesystem_link` runs `"/bin/ln", args: ["--no-dereference", "--force", "--symbolic", source, target]` ([symlinked.rb L109–L113](https://github.com/Homebrew/brew/blob/7f45a2a9bad007451e66917011531e5d7d310da5/Library/Homebrew/cask/artifact/symlinked.rb#L109-L113)). So on disk: real file at `<prefix>/Caskroom/sandcastle/<version>/sandcastle`, symlinks `<prefix>/bin/sandcastle` and `<prefix>/bin/sc` pointing at it.

### Go-side mechanics

- `os.Executable()` docs: "There is no guarantee that the path is still pointing to the correct executable. If a symlink was used to start the process, depending on the operating system, the result might be the symlink or the path it pointed to. If a stable result is needed, path/filepath.EvalSymlinks might help." — [pkg.go.dev/os#Executable](https://pkg.go.dev/os#Executable). (On macOS and Linux it in practice returns the invoked path — the symlink — but the contract explicitly does not promise which; code must handle both.)
- Two complementary checks, both grounded in the layout above:
  1. **Symlink-prefix check (what gh/flyctl do):** compare the *unresolved* `os.Executable()` result against `$(brew --prefix)/bin/`. Handles both `sc` and `sandcastle` invocation names identically (both symlinks live in the same dir). Fails if `brew` is not on PATH (both gh and flyctl treat that as "not Homebrew" and fall through — see Prior art) or if the executable path is already resolved by the OS.
  2. **`EvalSymlinks` + `/Caskroom/` substring:** resolve with `filepath.EvalSymlinks` and check for `/Caskroom/` in the resolved path. Works without brew on PATH and regardless of which alias was invoked, since both symlinks resolve into the Caskroom; the string `Caskroom` appears only in Homebrew layouts (including custom prefixes). Caveat: a hardlink or a user-made copy of the binary outside the Caskroom defeats it (as it defeats every path-based check); a user-made symlink *into* the Caskroom still detects correctly, which is the desired answer.
- **What breaks each strategy:** PATH lookups of `os.Args[0]` are unreliable (flyctl guards this with `exec.LookPath` + `EvalSymlinks` fallback, [update.go L351–L360](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L351-L360)); brew missing from PATH breaks strategy 1 (gh returns `false` from `isUnderHomebrew` on `safeexec.LookPath("brew")` failure); `$HOMEBREW_PREFIX` is only set in shells that ran `brew shellenv`, so it's a hint, not a source of truth. Notably, **neither gh nor flyctl uses the Caskroom/Cellar-substring approach** — both are (or historically were) formulae, and the `bin`-prefix check covers formulae and casks uniformly. For a cask-only binary, checking `/Caskroom/` after `EvalSymlinks` is the strictest brew-independent test; no production CLI was found doing exactly that (flagged as unverified-as-prior-art).
- gh documents the symlink-vs-resolved-path trap directly, in the doc comment on `executable()`: "This is needed primarily for Homebrew, which installs software under a location such as `/usr/local/Cellar/gh/1.13.1/bin/gh` and symlinks it from `/usr/local/bin/gh`. When the version is upgraded, Homebrew will often delete older versions, but keep the symlink. Because of this, we want to refer to the `gh` binary as `/usr/local/bin/gh` and not as its internal Homebrew location." — [cmd.go L425–L441](https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/ghcmd/cmd.go#L425-L441). Lesson: *detect* via the resolved path if you like, but never *store or re-exec* the resolved Caskroom path — it dies at the next upgrade.

## Delegating vs self-replacing

### POSIX / macOS file-replacement facts

- POSIX `unlink()`: "If one or more processes have the file open when the last link is removed, the link shall be removed before unlink() returns, but the removal of the file contents shall be postponed until all references to the file are closed." — [POSIX.1-2017 unlink()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/unlink.html). So unlink-and-replace (new inode) under a running process is safe; the running process keeps executing its old inode.
- Overwriting **in place** (same inode) is the dangerous case on macOS: Apple DTS (Quinn "The Eskimo") explains that the kernel validates code-signature integrity of loaded executable pages and **kills the process** (`SIGKILL`, "code signature invalid") if the backing file is modified in place; the sanctioned pattern is remove-then-copy or copy-to-temp-then-`mv` so a **new inode** is created — [Apple Developer Forums thread 696460](https://developer.apple.com/forums/thread/696460), which points at Apple's "Updating Mac Software" documentation ([developer.apple.com/documentation/security/updating-mac-software](https://developer.apple.com/documentation/security/updating_mac_software)).
- Homebrew's cask upgrade is the safe pattern: in `Cask::Upgrade.upgrade_cask` it runs `old_cask_installer.start_upgrade` ("Move the old cask's artifacts back to staging"), then `new_cask_installer.stage`, then `install_artifacts(predecessor: old_cask)` (recreates `bin` symlinks via `ln -sfn`, see above), and only on success `old_cask_installer.finalize_upgrade` ("If successful, wipe the old cask from staging"), with a rollback path (`purge_versioned_files` / `revert_upgrade`) on error — [upgrade.rb L432–L477](https://github.com/Homebrew/brew/blob/7f45a2a9bad007451e66917011531e5d7d310da5/Library/Homebrew/cask/upgrade.rb#L432-L477). Old and new versions are different Caskroom directories; nothing is overwritten in place, so a currently-running `sc` survives the upgrade and the *next* invocation through the `bin` symlink gets the new version.

### Practical concerns of exec'ing brew from inside the CLI (what real CLIs concluded)

- `brew upgrade` is slow and noisy, may update the whole dependency graph ("everything a formula depends on, and everything that depends on it in turn, needs to be upgraded" — [FAQ](https://docs.brew.sh/FAQ)), can prompt (sudo for some artifacts), and can itself be broken or lag the release. gh's answer: never run it — just print `To upgrade, run: brew upgrade gh`, and even *suppress the notice entirely* for Homebrew users within 24h of a release "before the version bump had a chance to get merged into homebrew-core" ([cmd.go L256–L267](https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/ghcmd/cmd.go#L256-L267)). The lag problem is real: Deno's own team acknowledged Homebrew "tends to lag behind … a couple patch versions to an entire minor version" ([denoland/deno discussion #25540](https://github.com/denoland/deno/discussions/25540), [issue #25298](https://github.com/denoland/deno/issues/25298)).
- flyctl's answer: run it, but wrap it — it pre-runs `brew update` (tolerating failure with a debug log), then executes the upgrade command through the user's `$SHELL -c` with stdio wired through, printing `Running automatic upgrade [brew upgrade flyctl]` ([update.go L269–L326](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L269-L326)). It also queries the *Homebrew API* rather than fly.io for the latest version when brew-managed, so it never advertises a version brew can't deliver ([L128–L133](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L128-L133), [`latestHomebrewRelease` L161](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L161)).

## This repo's cask

Live file [`Casks/sandcastle.rb` @ 221e365](https://github.com/thieso2/homebrew-tap/blob/221e3650861e0b1cab192fcb5be1b7f63ad5e660/Casks/sandcastle.rb), header "This file was generated by GoReleaser. DO NOT EDIT." Structure (fetched verbatim 2026-07-17); generated by this repo's `.goreleaser.yaml` `homebrew_casks` section:

- **Two binary stanzas**: `binary "sandcastle", target: "sc"` *and* `binary "sandcastle"` → symlinks `$(brew --prefix)/bin/sc` and `$(brew --prefix)/bin/sandcastle`, both pointing at `$(brew --caskroom)/sandcastle/0.1.0/sandcastle`. (The other role names — `sc-adm`, `sandcastle-admin` — are **not** in the cask; only the repo's `make build` creates those symlinks locally.)
- `version "0.1.0"`; per-platform `on_macos/on_linux` × `on_intel/on_arm` blocks each carrying `sha256` and a GitHub-releases `url … verified: "github.com/moyn-dev/sandcastle-incus/"`.
- `livecheck do skip "Auto-generated on release." end` — brew's livecheck is disabled; the tap is only updated by GoReleaser on tag push.
- `postflight do if OS.mac? system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/sandcastle"] end end` — exactly the pattern GoReleaser documents for unsigned binaries: "you still have the option to tell macOS to remove the quarantine bit from the binary on a post install hook", with the same `xattr -dr com.apple.quarantine "#{staged_path}/foo"` snippet — [goreleaser.com/customization/homebrew_casks](https://goreleaser.com/customization/homebrew_casks/) ("Signing and Notarizing"; casks replaced the deprecated formula-based `brews` pipe in GoReleaser v2.10).

### What in-place self-replacement bypassing brew would break here

- **Symlink target = Caskroom mutation.** `<prefix>/bin/sc` is a symlink into `Caskroom/sandcastle/0.1.0/`; "replacing the binary" through the symlink rewrites the Caskroom's staged copy — brew's on-disk state no longer matches the recorded install.
- **Version divergence.** Brew still believes 0.1.0 is installed. When 0.1.1 reaches the tap, `brew upgrade` happily clobbers the self-updated binary (fine); but if the self-update went *ahead* of the tap, `brew upgrade` later **downgrades silently**, and `brew reinstall --cask sandcastle` restores the old recorded version at any time. sha256 is only checked at download time, so a mutated Caskroom copy isn't detected — it's just replaced.
- **Quarantine.** The cask's `postflight` xattr strip only runs under brew. A bypassing self-updater would have to handle quarantine itself — however, per Apple, quarantine on newly created files is **opt-in**: `LSFileQuarantineEnabled` — "`true`: Files created by this app are quarantined by default … `false` (**Default**): Files created by this app are not quarantined by default" ([Apple Launch Services Keys reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html)). A plain Go CLI downloading over HTTP does not opt in, so its written file carries no quarantine xattr and Gatekeeper's download check would not fire. The real macOS hazard is the in-place-overwrite/SIGKILL issue above, plus the fact that the unsigned replacement loses nothing (the shipped binary is unsigned anyway).
- **Rollback/uninstall integrity.** `brew uninstall`/`upgrade` operate on the artifact list of the *recorded* caskfile; a binary swapped outside brew still gets unlinked/removed correctly (paths unchanged), so uninstall survives — the damage is limited to version truth, not orphaned files.

## Prior art (gh, deno, flyctl)

### gh (cli/cli) — notice only, never self-replaces

- No self-update exists; feature requests remain open, with the stated preference that "if users are installing via a package manager … they should upgrade gh over the same package manager" and that self-update "may conflict with package managers" — [issue #3486](https://github.com/cli/cli/issues/3486), [discussion #4630](https://github.com/cli/cli/discussions/4630).
- Update check: `internal/update/update.go` polls the GitHub releases API at most every 24h, state-filed, gated by `GH_NO_UPDATE_NOTIFIER`/CI/TTY checks — [update.go](https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/update/update.go).
- Detection, verbatim ([cmd.go L333–L347](https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/ghcmd/cmd.go#L333-L347)):

  ```go
  // Check whether the gh binary was found under the Homebrew prefix
  func isUnderHomebrew(ghBinary string) bool {
      brewExe, err := safeexec.LookPath("brew")
      if err != nil {
          return false
      }
      brewPrefixBytes, err := exec.Command(brewExe, "--prefix").Output()
      if err != nil {
          return false
      }
      brewBinPrefix := filepath.Join(strings.TrimSpace(string(brewPrefixBytes)), "bin") + string(filepath.Separator)
      return strings.HasPrefix(ghBinary, brewBinPrefix)
  }
  ```

- Use of it ([cmd.go L254–L270](https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/ghcmd/cmd.go#L254-L270)): if Homebrew-managed and the release is <24h old, print nothing; otherwise print the new-version banner and, if Homebrew-managed, `To upgrade, run: brew upgrade gh`.

### deno (denoland/deno) — self-replaces; **no** package-manager detection (ticket's assumption not confirmed)

- The full current [`cli/tools/upgrade.rs` @ fe70a4e](https://github.com/denoland/deno/blob/fe70a4ec3d62146940899c64525e2f93e7884949/cli/tools/upgrade.rs) was fetched and grepped for `homebrew`, `brew`, `winget`, `package manager`, `managed`: **there is no code that detects a Homebrew/package-manager install or refuses/warns on `deno upgrade`.** `deno upgrade` swaps the current executable unconditionally (with a Windows-specific rename/terminate dance for file locking).
- The only package-manager mention is an incidental hint inside the root-ownership error in `set_exe_permissions` ([upgrade.rs L2020–L2033](https://github.com/denoland/deno/blob/fe70a4ec3d62146940899c64525e2f93e7884949/cli/tools/upgrade.rs#L2020-L2033)):

  ```rust
  bail!(
    concat!(
      "You don't have write permission to {} because it's owned by root.\n",
      "Consider updating deno through your package manager if its installed from it.\n",
      "Otherwise run `deno upgrade` as root.",
    ),
    output_exe_path.display()
  );
  ```

- **Flagged as unverified/false:** the belief that deno checks "whether the current exe path resolves under homebrew … and prints 'installed via a package manager, use that to upgrade'" does not match current source. No such condition exists in `upgrade.rs`, nor a denoland/deno issue documenting one; the surrounding evidence (team steering users off Homebrew because it lags — [#25540](https://github.com/denoland/deno/discussions/25540)) suggests deno's *policy* is the opposite: self-update even over brew installs, which then desynchronizes brew — a live example of the failure mode in "This repo's cask" above.

### flyctl (superfly/flyctl) — detects brew and **executes** `brew upgrade flyctl`

All in [`internal/update/update.go` @ 56c828f](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go):

- Detection ([L199–L245](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L199-L245)), memoized; same shape as gh but against `os.Executable()`:

  ```go
  func brewBinDir() (string, error) {
      return _brewBinDir.Get(func() (string, error) {
          brewExe, err := safeexec.LookPath("brew")
          if err != nil { return "", errBrewNotFound }
          brewPrefixBytes, err := exec.Command(brewExe, "--prefix").Output()
          if err != nil { return "", err }
          brewBinPrefix := filepath.Join(strings.TrimSpace(string(brewPrefixBytes)), "bin") + string(filepath.Separator)
          return brewBinPrefix, nil
      })
  }

  // IsUnderHomebrew reports whether the fly binary was found under the Homebrew prefix.
  func IsUnderHomebrew() bool {
      if runtime.GOOS == "windows" { return false }
      val, err := _isUnderHomebrew.Get(func() (bool, error) {
          flyBinary, err := os.Executable()
          if err != nil { return false, err }
          brewBinPrefix, err := brewBinDir()
          if err != nil { return false, err }
          return strings.HasPrefix(flyBinary, brewBinPrefix), nil
      })
      if err != nil { return false }
      return val
  }
  ```

- Command selection ([L247–L253](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L247-L253)): `if IsUnderHomebrew() { return "brew upgrade flyctl" }`, else the fly.io install script (curl|sh or PowerShell).
- Execution ([`UpgradeInPlace` L269–L326](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L269-L326)): when brew-managed, first `exec.Command(brewExe, "update").Run()` (failure only debug-logged), then runs `upgradeCommand()` via `$SHELL -c` (default `/bin/bash`) with the user's stdio attached: `fmt.Fprintf(io.ErrOut, "Running automatic upgrade [%s]\n", command)`.
- Stable-path discipline ([`GetCurrentBinaryPath` L337–L362](https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L337-L362)): when brew-managed it prefers the stable `<brewBin>/flyctl` symlink; otherwise `exec.LookPath(os.Args[0])` + `filepath.EvalSymlinks`. `CanUpdateThisInstallation()` returns `true` for Homebrew (because it can delegate) and otherwise requires the binary to live in the fly install dir. It also fetches the latest version from Homebrew's own API when brew-managed (see above) so it never offers a version the cask/formula can't provide.

### One-liners (adjacent tools)

- **rustup**: package-manager builds compile with the `no-self-update` feature; `rustup update`/`self update` then prints "self-update is disabled for this build of rustup / any updates to rustup will need to be fetched with your system package manager" — [self_update.rs L298–L302](https://github.com/rust-lang/rustup/blob/master/src/cli/self_update.rs) (build-time opt-out rather than runtime detection).
- **uv**: "When uv is installed via the standalone installer, it can update itself on-demand: `uv self update` … When another installation method is used, self-updates are disabled. Use the package manager's upgrade method instead." — [docs.astral.sh/uv installation](https://docs.astral.sh/uv/getting-started/installation/).
- **npm**: not investigated in depth (out of time-box); npm updates itself through itself (`npm install -g npm`), which is its own package manager rather than a bypass — no primary citation gathered, flagged as unverified.

## Recommendation facts (no policy, just what the facts support)

1. Detection that matches prior art: unresolved `os.Executable()` prefix-checked against `$(brew --prefix)/bin/` via `brew --prefix` (gh, flyctl — both return "not Homebrew" if brew isn't on PATH). A brew-independent complement with no cited prior art but grounded in the documented layout: `filepath.EvalSymlinks` + `/Caskroom/` substring — it works for both the `sc` and `sandcastle` symlinks and for custom prefixes.
2. Never persist or re-exec the resolved Caskroom path; always use the `<prefix>/bin` symlink — Homebrew deletes old versioned dirs on upgrade but keeps the symlink (gh's `executable()` comment).
3. Running `brew upgrade --cask sandcastle` while `sc` is executing is safe: cask upgrade is stage-new/relink/wipe-old (new inode), and POSIX keeps the running process's inode alive; in-place overwrite is the only pattern macOS punishes (SIGKILL on code-signature page mismatch — and would in any case mutate the Caskroom).
4. Self-replacing while brew-managed demonstrably desynchronizes brew (deno's situation): next `brew upgrade` can silently downgrade, `brew reinstall` reverts, and the tap's `livecheck` is skipped so brew has no way to notice. Both CLIs that thought this through (gh, flyctl) delegate to brew for brew-managed installs — gh by printing the command, flyctl by running it interactively; gh additionally suppresses the nag for <24h-old releases so users aren't told to upgrade before the tap catches up (directly applicable here, since the tap updates only on GoReleaser tag push).
5. Quarantine is a non-issue for a hypothetical Go self-downloader (files written by a non-`LSFileQuarantineEnabled` process aren't quarantined, per Apple), but the shipped binary is unsigned and depends on the cask's `postflight` xattr strip for the *brew-downloaded* copy — another reason the brew path is the supported one on macOS.

## Sources

- https://docs.brew.sh/Installation — default prefixes
- https://docs.brew.sh/FAQ — custom-prefix warning; upgrade dependency behavior
- https://docs.brew.sh/Manpage — `--prefix`, `--caskroom`, `--cellar`, `brew shellenv`/`HOMEBREW_PREFIX`
- https://docs.brew.sh/Cask-Cookbook#stanza-binary — binary stanza, Caskroom layout, postflight
- https://github.com/Homebrew/brew/blob/7f45a2a9bad007451e66917011531e5d7d310da5/Library/Homebrew/cask/upgrade.rb#L432-L477 — cask upgrade sequence
- https://github.com/Homebrew/brew/blob/7f45a2a9bad007451e66917011531e5d7d310da5/Library/Homebrew/cask/artifact/binary.rb and …/symlinked.rb#L109-L113 — binary = symlink via `ln -sfn`
- https://github.com/thieso2/homebrew-tap/blob/221e3650861e0b1cab192fcb5be1b7f63ad5e660/Casks/sandcastle.rb — live cask
- https://goreleaser.com/customization/homebrew_casks/ — generated cask contents; unsigned-binary xattr postflight
- https://pkg.go.dev/os#Executable — symlink caveat
- https://pubs.opengroup.org/onlinepubs/9699919799/functions/unlink.html — unlink-while-open semantics
- https://developer.apple.com/forums/thread/696460 (+ https://developer.apple.com/documentation/security/updating_mac_software) — in-place overwrite kills signed running processes; atomic replace
- https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html — `LSFileQuarantineEnabled` default `false`
- https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/ghcmd/cmd.go#L254-L270, #L333-L347, #L425-L446; https://github.com/cli/cli/blob/2af8c115be240a8018add33bf5c7a9ba5070a62c/internal/update/update.go; https://github.com/cli/cli/issues/3486; https://github.com/cli/cli/discussions/4630 — gh
- https://github.com/denoland/deno/blob/fe70a4ec3d62146940899c64525e2f93e7884949/cli/tools/upgrade.rs#L2020-L2033; https://github.com/denoland/deno/discussions/25540; https://github.com/denoland/deno/issues/25298 — deno
- https://github.com/superfly/flyctl/blob/56c828f79ca41a154d5983e22b90725da37e44f5/internal/update/update.go#L128-L133, #L199-L266, #L269-L326, #L337-L362 — flyctl
- https://github.com/rust-lang/rustup/blob/master/src/cli/self_update.rs (L298–L302) — rustup no-self-update
- https://docs.astral.sh/uv/getting-started/installation/ — uv self-update policy

**Unverified / corrected items:** deno's alleged Homebrew detection (not present in current source — corrected above); npm behavior (not researched); no production CLI found using the `EvalSymlinks`+`/Caskroom/` check specifically (the technique is layout-derived, not prior-art-cited).
