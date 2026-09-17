# Directory-local remote and project selection

## Agreed behavior

The active remote and project belong to the working directory. Read `.sandcastle`
in that directory, then each parent up to the filesystem root; stop at the first
file. Do not merge ancestor files. Explicit command flags/reference prefixes and
exported environment variables take precedence. When no file exists, retain the
existing global fallback: the shared Incus Sandcastle default remote (when
eligible), then the user config; project comes from the user config/default.

`sc project switch` and `sc remote switch` update that nearest file. With no file,
they create `.sandcastle` in the current directory containing both the remote and
project. They report its absolute path. These commands do not change global
Sandcastle defaults, the shared Incus default remote, or remote project pins.

`sc project list` and `sc remote list` report the absolute path of the file read,
or explicitly say that no `.sandcastle` was found and global fallback applies.
The current marker reflects the effective selection, including environment
variables. Project-list JSON retains its existing fields and adds `config_path`
(empty when no local file exists). `sc config show` also reports the source.

## File format

```yaml
remote: home
project: web
remote_projects:
  home: web
  office: backend
```

The YAML file contains a required `remote` and `project`, plus optional
`remote_projects` history. A remote switch restores its remembered project in
this file; without history, use the remote's existing Incus project pin, otherwise
`default`. Project switches update the remembered project. History is local to
this file, so independent checkouts do not affect one another.

Unknown fields, invalid YAML, missing required fields and unreadable files are
errors naming the path. Do not silently target a global fallback after a bad
local file. Writes replace the file atomically. Discovery traverses filesystem
parents (not a Git boundary); an existing file symlink is followed when writing.

Credentials and enrollment metadata remain in `~/.config/sandcastle/config.yml`
and the existing Incus directories. On each invocation, resolve the selected
remote's Auth Hostname, tenant, token and broker from the global enrollment maps
in memory. Never persist credentials in `.sandcastle` or borrow a different
remote's credentials for an unknown local remote. Environment overrides remain
available for explicit invocations.

## Compatibility boundaries

This intentionally supersedes ADR-0021's project-switch write-through behavior.
`sc` and `sc incus` use directory selection; raw `incus` keeps its independent
global defaults. Existing login/enrollment behavior and explicit `sc config
set/unset` operations on global fallback configuration remain available. They do
not override a `.sandcastle` file. Other settings and admin credentials stay global.

## Validation

Cover nearest-ancestor reads/writes, local file shadowing, creation with no file,
invalid files stopping lookup, environment precedence, fallback without a file,
per-remote credentials, local project history, source reporting including JSON,
and byte-for-byte preservation of global Sandcastle/Incus files during switches.
Live protocol: `docs/e2e-sc2.md`, directory selection checks in Phase 2.
