# Sandcastle

Sandcastle provides Incus-backed development environments scoped by tenant and
project, with simple CLI management for containers and later VMs.

> The domain vocabulary is in [`docs/glossary.md`](docs/glossary.md); the architecture overview is in [`docs/topology.md`](docs/topology.md). Use those terms in code, comments, and messages.

## Language

**Tenant**:
An admin-created top-level namespace that owns projects, DNS naming, and access boundaries.
_Avoid_: Owner, account, named tenant

**Personal Tenant**:
An automatically created Tenant scoped to one allowlisted User; it belongs to the User whose Sandcastle User Key names it.
_Avoid_: User-owned tenant, GitHub tenant

**Shared Tenant**:
An admin-created Tenant that several Users manage together: its Tenant Members are recorded in Tenant Metadata (`v2.members`), every member's login SSH key is authorized on its Machines, and every member can act on it from the CLI after `sc tenant switch`. Created with `sc-adm create tenant --member`, extended with `sc-adm tenant grant`.
_Avoid_: Team tenant, group tenant, org tenant

**Tenant Member**:
A User granted Tenant Access to a Shared Tenant without owning it. Prerequisite: the User has completed CLI Device Login on the install (their Personal Tenant carries the login SSH key the shared Machines authorize) and sits on the tenant's tailnet.
_Avoid_: Collaborator, guest user

**Tenant DNS Suffix**:
The tenant-chosen final label(s) of Sandcastle private hostnames; defaults to the tenant name.
_Avoid_: Tenant TLD, tenant domain

**Personal Tenant DNS Suffix**:
The Tenant DNS Suffix initially derived from the allowlisted GitHub Username for a Personal Tenant.
_Avoid_: Numeric GitHub account ID suffix, auto-updated GitHub username

**Machine Private Hostname**:
The canonical private DNS name of a Machine: `<machine>.<project>.<Tenant DNS Suffix>`, for every project including default.
_Avoid_: Short hostname, machine FQDN

**Default Project Short Hostname**:
The alias `<machine>.<Tenant DNS Suffix>` that resolves to the default project's machine of that name; machines in other projects have no short form.
_Avoid_: Unique-name short alias, first-wins short name

**Public DNS Zone**:
A public DNS domain (e.g. `hase.de`) an admin registers with the Sandcastle install, together with the credential that lets the Auth App manage records in it. Cloudflare-hosted for now.
_Avoid_: Tenant zone, install zone, DNS provider account

**Project Domain**:
The public DNS name a Project claims under a Public DNS Zone (e.g. `baum.hase.de`). Optional; a Project without one gives its Machines no derived public name (they keep their Machine Private Hostname and may still carry explicit Machine Public Hostnames). Reserved install-wide, first come, including everything below it.
_Avoid_: Project suffix, project zone

**Project Certificate**:
The publicly trusted DNS-01 certificate owned by a Project with a Project Domain. Its SANs are the domain and `*.<domain>`. The Auth App stores it once and distributes it to the Project's Machines. Derived names and explicit one-label aliases use this certificate without per-machine orders; deeper names, outside names, zone apex names and explicitly requested per-machine wildcards use per-name certificates.


**Machine Public Hostname**:
One of a Machine's set of public DNS names: the *derived* name `<machine>.<Project Domain>` when the Project has a Project Domain, plus any *explicit* names the tenant claims under a Public DNS Zone (`sc create --hostname`, `sc hostname add`). A Machine has zero or more; it always keeps its Machine Private Hostname beside them. An explicit name reserves itself and its wildcard subtree install-wide, first come. Distinct from a Public Route: a Machine Public Hostname resolves to the Machine's tenant-private address and is reachable only over the Tenant Tailnet.
_Avoid_: Public hostname, route hostname, public machine, zone-mode machine

**Naming Mode**:
Superseded by ADR-0028 (2026-09-13). ADR-0027's per-Machine `private`/`zone` choice fixed at creation no longer exists: every Machine has its Machine Private Hostname and additionally a set of Machine Public Hostnames. The literal `private` survives only as the value of the legacy `user.sandcastle.v2.public-hostname` instance key, read for one release.
_Avoid_: Zone-mode project, private-mode project, TLS mode, zone mode, private mode

**Caddy Setup Marker**:
The file a Machine's Caddy setup leaves behind (`/etc/sandcastle/caddy.ready`) stating which names it configured: the Machine Private Hostname (`PRIVATE=`) and every Machine Public Hostname whose certificate it rendered a site block for (`PUBLIC=`), plus when (`RENDERED=`). The Auth App delivers a certificate to a Machine only when the marker is present in this per-name form; the machine then re-renders with `sandcastle-caddy-setup --refresh`.
_Avoid_: Setup flag, ready file

**Freeform Machine**:
A Machine a Tenant creates directly with native Incus tooling instead of `sc create`. It inherits the Project's profile, so it is registered in DNS and may receive a certificate like any other Machine, but Sandcastle records nothing about it until the Auth App first sees it.
_Avoid_: Unmanaged machine, raw instance, incus launch machine

**Machine Certificate**:
The publicly trusted certificate the Auth App obtains and holds for one Machine Public Hostname and its one-level wildcard, and installs into the Machine. Its state is derived, never stored: `pending`, `issued`, `installed`, `renewing`, `failed`.
_Avoid_: Leaf, machine cert, active certificate

**GitHub Username Tenant Name**:
The normalized GitHub username form allowed for Personal Tenant names.
_Avoid_: Generic tenant name validation

**User**:
An identity that can manage Sandcastle resources within one or more tenants.
_Avoid_: Owner

**Sandcastle User Key**:
The Sandcastle identifier for a User, derived from the allowlisted GitHub Username in v1.
_Avoid_: Numeric GitHub account ID as user-facing identity, email as identity key

**GitHub Username**:
The GitHub login name used as the Sandcastle User Key, Personal Tenant name, and Personal Tenant DNS Suffix in v1.
_Avoid_: Display-only metadata

**Normalized GitHub Username**:
The lowercase form of a GitHub Username used for Sandcastle identifiers.
_Avoid_: GitHub display casing

**GitHub Email**:
The email address collected from GitHub OAuth and stored as inactive User metadata in v1.
_Avoid_: User identity, notification channel in v1

**Login Allowlist**:
The admin-managed set of GitHub accounts allowed to authenticate to Sandcastle.
_Avoid_: Tenant Access, user registry

**Sandcastle Admin**:
A User allowed to manage login allowlisting and tenant access delegation.
_Avoid_: Tenant owner, infrastructure user

**GitHub OAuth Login**:
The browser sign-in flow that maps a GitHub identity to a Sandcastle User.
_Avoid_: GitHub OpenID login, GitHub OIDC login

**Web Registration**:
The browser flow that creates or confirms a Sandcastle User session after GitHub OAuth Login without provisioning tenant infrastructure.
_Avoid_: Tenant registration, browser tenant creation

**Onboarding Page**:
The signed-in Auth App page that shows GitHub identity status, allowlist status, CLI installation instructions, and the CLI login command.
_Avoid_: Browser provisioner, SSH key upload page

**Sandcastle OIDC Provider**:
The public issuer that signs Sandcastle workload identity tokens for external cloud trust.
_Avoid_: GitHub OIDC provider, OAuth login provider

**Per-Tenant OIDC Issuer**:
The tenant-scoped Sandcastle OIDC issuer used for external cloud trust isolation.
_Avoid_: Global tenant claim filter, per-project issuer

**Workload Identity Token**:
A short-lived OIDC token that identifies both the User and the Machine for external cloud trust.
_Avoid_: Sandbox token, cloud key

**Cloud Identity Audience**:
The external cloud provider audience value that a Workload Identity Token is minted for.
_Avoid_: Auth Hostname, OIDC issuer, service account email

**OIDC Signing Key**:
The Auth App private key used to sign Workload Identity Tokens.
_Avoid_: OAuth client secret, GitHub secret

**Machine Runtime Secret**:
A per-Machine secret used by the Machine to request Workload Identity Tokens from the Auth App.
_Avoid_: User token, Incus certificate, cloud credential

**Cloud Identity Config**:
A User-owned external cloud trust configuration that a Machine can use for workload identity.
_Avoid_: Tenant cloud config, project cloud setting

**Auth App**:
The infrastructure service that handles GitHub login, CLI device login, user registry, and workload identity issuing.
_Avoid_: Incus metadata app

**Infrastructure Seed File**:
An operator-supplied, portable, secret-bearing bootstrap bundle for shared infrastructure configuration and reusable working public TLS material.
_Avoid_: Environment-only deployment, tenant backup, Auth Database backup

**Deployment Name**:
The local operator name that identifies one Sandcastle shared infrastructure seed and stack.
_Avoid_: Tenant name, Auth Hostname, Incus project name

**Auth Hostname**:
The public HTTPS hostname for the Auth App and Sandcastle OIDC Provider issuer.
_Avoid_: Route hostname, tenant hostname

**Auth Database**:
The Auth App's persistent SQLite store for login identities, device login state, token records, and audit state.
_Avoid_: Tenant Metadata, Incus project config

**CLI Device Login**:
The browser-assisted CLI sign-in flow that lets a User authorize a local CLI without pasting long-lived credentials.
_Avoid_: API token login, password login

**Incus Certificate Add Token**:
A one-time Incus token that lets the CLI add its locally generated client certificate as the User's restricted Incus credential.
_Avoid_: Incus auth token, Sandcastle API token, private key

**User SSH Public Key**:
The single current public SSH key uploaded by the CLI during device login and authorized for Machine shell access.
_Avoid_: SSH private key, browser-uploaded SSH key, named SSH key set

**Machine SSH Access**:
The user-facing shell connection path into a Machine using the User's SSH private key.
_Avoid_: Incus exec as user shell, browser shell

**Machine Private IPv4 Address**:
The Tenant Network IPv4 address assigned to a managed Machine and configured inside the guest for Machine SSH Access and private machine services.
_Avoid_: Incus list IP, Tailscale Machine IP

**Tailscale Machine IP**:
The Tailscale-assigned IP address used by the CLI for Machine SSH Access.
_Avoid_: Local DNS SSH target, Incus internal IP

**Tailscale Prerequisite**:
The requirement that the user's local machine has a working Tailscale client connected to the relevant Tenant Tailnet before Machine SSH Access can succeed.
_Avoid_: Optional VPN setup, silent CLI Tailscale enrollment

**Sandcastle SSH Key**:
The CLI-generated local SSH key pair used when the user has not selected or already created a default SSH key.
_Avoid_: Server-generated SSH key, tenant SSH key

**Login Readiness**:
The completed CLI state in which credentials, SSH access, Personal Tenant, Default Project, and Tailscale-backed Tenant Infrastructure are ready for Machine creation and connection.
_Avoid_: OAuth completion, browser login success

**CLI Login Result**:
The structured final response from CLI Device Login that lets the CLI persist local configuration and print the next command.
_Avoid_: Browser session payload, provisioning log

**Created By**:
Audit metadata recording which user created a resource.
_Avoid_: Resource owner

**Tenant Access**:
A user's permission to manage all projects and machines in a tenant: implied for a Personal Tenant's owner, recorded as Tenant Membership for a Shared Tenant. The Auth App applies it to every tenant-plane request, which carries the CLI's Current Tenant (`X-Sandcastle-Tenant`, defaulting to the caller's Personal Tenant).
_Avoid_: Project grant

**Project**:
A named namespace inside a tenant for grouping Sandcastle runtime resources.
_Avoid_: Incus project when discussing the product concept, project settings

**Incus Project Mapping**:
The rule that a Sandcastle tenant is represented by one infra Incus project `<prefix>-<tenant>` (`kind=infra`) plus one app Incus project per Sandcastle project, named `<prefix>-<tenant>-<project>` (`kind=project`).
_Avoid_: One Incus project per tenant, `sc-<tenant>` single-project tenant

**Incus Instance Name**:
The Incus-level machine name inside a tenant's app Incus project; it is the bare Sandcastle machine name.
_Avoid_: `<project>-<machine>` compound instance name

**Tenant Metadata**:
The authoritative Sandcastle state stored on the tenant's infra Incus project.
_Avoid_: Local project registry

**Local DNS Installation**:
Machine-local resolver configuration that forwards a tenant DNS suffix to Sandcastle DNS.
_Avoid_: Project DNS install

**Tenant Network**:
The private network shared by all projects and machines in a tenant.
_Avoid_: Project network

**Tenant Infrastructure**:
The DNS, Tailscale, and certificate authority services shared by all projects in a tenant.
_Avoid_: Project sidecars

**Tenant Tailnet**:
The Tailscale network dedicated to exactly one Tenant. It is **bring-your-own**: the
Tenant supplies their own Tailscale auth key at registration and the Tenant's own
Sidecar joins that network. Sandcastle hosts no coordinator of its own (no Headscale).
Tailnet membership is the **default and main operation mode** of every Sandcastle,
not an optional add-on: the Sidecar joins at tenant creation and every access path
(CLI, SSH, DNS, Incus Reach) rides the tailnet.
_Avoid_: Shared Sandcastle tailnet, project tailnet, platform-hosted tailnet, optional tailnet

**Sidecar** (Tenant Sidecar):
The per-Tenant instance that joins the Tenant Tailnet and is the Tenant's single
doorway onto it. It carries the Tenant's DNS (CoreDNS) and, as the **Incus Reach**,
proxies the host's Incus API onto the Tenant Tailnet so the Tenant can reach it
without the host being on any tailnet.
_Avoid_: Project sidecar

**Incus Reach**:
How a Tenant reaches the host's Incus API. The host is on no tailnet; the Tenant's
Sidecar forwards its own tailnet address to the host's Incus, so a client on the
Tenant Tailnet connects to the Sidecar's tailnet address and the connection lands on
the host's Incus. Authentication is unchanged — mutual TLS with the Tenant's
restricted client certificate is the isolation boundary; the tailnet only provides
reachability.
_Avoid_: public Incus endpoint, host-on-tailnet

**Tenant CA**:
The certificate authority used for private machine TLS hostnames in a tenant.
_Avoid_: Project CA

**Tenant Storage**:
Persistent tenant volumes whose default paths are partitioned by project and machine names.
_Avoid_: Project storage volume

**Tenant Storage Share**:
An explicit grant that exposes a source Tenant's workspace directory to one or more recipient Tenants.
_Avoid_: Global share, public tenant storage

**Share Name**:
The stable path-safe user-facing name of a Tenant Storage Share, defaulting to the source path basename.
_Avoid_: Directory name, mount name

**Machine**:
A tenant project runtime environment that a user can list, create, connect to, or delete.
_Avoid_: Sandbox, add, enter, rm

**App Port**:
The machine's primary internal HTTP port.
_Avoid_: Route port

**Private Machine Proxy**:
The per-machine HTTP/HTTPS proxy that serves the machine's private hostname and forwards to its app port.
_Avoid_: Raw app port access as the primary URL

**Container**:
The default Machine type backed by an Incus container.
_Avoid_: Sandbox when discussing user-facing resources

**Machine Template**:
The base image profile used to create a machine.
_Avoid_: Project template

**Sandcastle Image**:
The OCI image that backs a Machine Template; the Base Image, the AI Image, and the Dev Image are its three variants.
_Avoid_: Container image, docker image

**Image Registry**:
The external OCI registry that distributes Sandcastle Images for an Incus host to pull and cache locally.
_Avoid_: Image store, docker hub

**Image Builder**:
The admin-managed infrastructure appliance that builds Sandcastle Images and publishes them to the Image Registry. Not a Machine.
_Avoid_: Build machine, sc container, builder Machine

**VM**:
A future Machine type backed by an Incus virtual machine.
_Avoid_: Separate product resource

**Default Project**:
The normal Project named `default` that exists in every tenant from tenant creation.
_Avoid_: Implicit project, projectless container bucket

**Current Tenant**:
The tenant selected by local CLI configuration for unqualified user commands.
_Avoid_: Owner, SANDCASTLE_OWNER, active account, logged-in tenant

**Rendered Version**:
The release whose cloud-init document a Machine booted with, frozen on the Machine at creation from the Project's profile; the profile itself records the release that last rendered it. A later re-render changes the profile, never the Machine.
_Avoid_: Profile version on a machine, image version, CLI version

**Sandcastle Path**:
The slash form of a reference, `/remote/tenant/project/machine`, absolute or relative to the Current Position, with `.`, `..`, `~` (home), `-` (previous) and shell globs in any segment. A second grammar beside the colon reference, selected by shape; a machine is its leaf.
_Avoid_: Resource path, URL, colon path

**Current Position**:
The remote, tenant and project every unqualified user command acts in, recorded per directory tree in the nearest `.sandcastle` and shown by `sc pwd`. It may stand above a project (at the tenant, remote or root level) after `sc cd ..`; the switch commands and `sc cd` both move it.
_Avoid_: Working directory, context, cwd, session position

**Current Project**:
The project selected by CLI input or local CLI configuration, defaulting to the Default Project.
_Avoid_: Projectless mode

## Relationships

- A **Tenant** has one or more **Projects**.
- A **Tenant** has exactly one **Incus Project Mapping**.
- A **Tenant** has one **Tenant Network** shared by all its **Projects**.
- A **Tenant** has one **Tenant Infrastructure** set shared by all its **Projects**.
- A **Tenant** has exactly one **Tenant Tailnet**.
- A **Tenant** has **Tenant Storage** shared by all its **Projects**.
- A **Tenant Storage Share** has exactly one source **Tenant** and one or more explicit recipient **Tenants**.
- A managed **Machine** has one **Machine Private IPv4 Address** on its **Tenant Network**.
- Managed **Machine** creation and mutation preserve the Machine's **Machine Private IPv4 Address** across Machine restarts.
- A **Tenant Storage Share** is between **Tenants** in the same Sandcastle deployment.
- A **Tenant Storage Share** has exactly one **Share Name**.
- A **Tenant Storage Share** can default its **Share Name** only when the source directory basename is path-safe.
- The combination of source **Tenant**, source **Project**, and **Share Name** identifies one **Tenant Storage Share**.
- A **Tenant Storage Share** keeps the same **Share Name** after creation.
- A **Tenant Storage Share** source directory is rooted in the source **Tenant Storage** workspace for an explicit **Project**.
- A **Tenant Storage Share** source directory must be below the project workspace root, not the project workspace root itself.
- A **Tenant Storage Share** source directory must exist when the share is created.
- A **Tenant Storage Share** source directory does not change after the share is created.
- A **Tenant Storage Share** exposes its source directory tree as-is.
- A **Tenant Storage Share** must not expose paths outside its source directory through symlink traversal.
- A **Tenant Storage Share** remains defined if its source directory later disappears or becomes boundary-unsafe, but is unavailable to recipient **Machines** until the source directory is available and safe again.
- A source **Tenant** may define multiple **Tenant Storage Shares** with overlapping source directories.
- Recipient **Machines** see **Tenant Storage Shares** under `/shared/<source-tenant>/<source-project>/<share-name>`.
- Unavailable **Tenant Storage Shares** do not appear as placeholder paths in recipient **Machines**.
- Recipient **Tenants** may not rename accepted **Tenant Storage Shares** locally.
- Source **Machines** access a **Tenant Storage Share** through their normal `/workspace` path, not through `/shared`.
- Source **Tenant** users write shared content through the normal source `/workspace` path.
- **Tenant Storage Share** data belongs to the source **Tenant's** storage.
- The source **Tenant** owns the offer and revocation state for a **Tenant Storage Share**.
- A recipient **Tenant** owns whether an offered **Tenant Storage Share** is accepted and visible.
- Adding a recipient **Tenant** to a **Tenant Storage Share** creates a pending offer for that recipient.
- A pending **Tenant Storage Share** offer remains pending until accepted, declined, or revoked.
- Removing a recipient **Tenant** from a **Tenant Storage Share** revokes the share for that recipient.
- A recipient **Tenant** exposes an accepted **Tenant Storage Share** read-only to all of its **Machines**.
- **Tenant Infrastructure** does not expose accepted **Tenant Storage Shares**.
- **Tenant Storage Share** acceptance is recorded for the recipient **Tenant**, not for an individual **User**.
- Accepting a **Tenant Storage Share** makes it visible to running and future recipient **Machines**.
- **Tenant Storage Share** visibility is reconciled from accepted share state to recipient **Machines**.
- All **Tenant Storage Shares** mounted under `/shared` are read-only.
- A **Tenant Storage Share** is visible in a recipient **Tenant** only after that recipient accepts the share.
- A recipient **Tenant** must not accept a **Tenant Storage Share** when its `/shared/<source-tenant>/<source-project>/<share-name>` path is already occupied.
- A recipient **Tenant** may decline an accepted **Tenant Storage Share** to remove it from that **Tenant's** **Machines**.
- A recipient **Tenant** may later accept a declined **Tenant Storage Share** while the source offer remains active.
- Revoking a **Tenant Storage Share** removes it from running recipient **Machines**.
- Deleting a **Tenant Storage Share** removes all of its recipient offers and acceptances.
- A **User** with **Tenant Access** to the source **Tenant** may grant or revoke its **Tenant Storage Shares**.
- A **User** with **Tenant Access** to a recipient **Tenant** may accept or decline **Tenant Storage Shares** offered to that **Tenant**.
- **Tenant Storage Share** lifecycle actions record the acting **User** for audit.
- A recipient **Tenant** may not re-share an inbound **Tenant Storage Share** to another **Tenant**.
- A source **Project** cannot be deleted while it has active **Tenant Storage Shares**.
- Deleting a source **Tenant** deletes its **Tenant Storage Shares**.
- Deleting a recipient **Tenant** removes that **Tenant's** inbound **Tenant Storage Share** acceptances.
- A **Deployment Name** maps to one default **Infrastructure Seed File** at `~/.config/sandcastle/<deployment-name>.seed.yml`.
- Shared infrastructure creation may create the default **Infrastructure Seed File** when it does not already exist.
- Shared infrastructure creation may update the **Infrastructure Seed File** only with captured reusable working TLS material, not with transient CLI or environment overrides.
- An **Infrastructure Seed File** is YAML with domain-shaped sections for infrastructure, authentication, routing, images, and reusable TLS material.
- An **Infrastructure Seed File** may contain deployment secrets and must be treated as private operator material.
- Reusable public TLS material in an **Infrastructure Seed File** belongs to a specific Auth Hostname and must not be restored for a different Auth Hostname.
- Shared infrastructure creation prepares configured Sandcastle images unless the image reference is a full external OCI source.
- Admin tenant creation requires only the **Tenant** name; infrastructure details are derived from admin configuration.
- Admin-created non-personal **Tenants** keep the existing Sandcastle tenant naming rule.
- The Auth App creates a **Personal Tenant** for an allowlisted **User** during first CLI Device Login.
- **Web Registration** creates or confirms a **User** session but does not create a **Personal Tenant**.
- The **Onboarding Page** does not accept SSH keys or provision tenant infrastructure.
- The **Onboarding Page** shows install instructions for supported CLI platforms and highlights the detected platform when possible.
- A **Personal Tenant** uses the **Normalized GitHub Username** as its Tenant identity in v1.
- A **Personal Tenant** name follows **GitHub Username Tenant Name** rules in v1.
- A **Personal Tenant DNS Suffix** is initialized from the allowlisted **Normalized GitHub Username**.
- A **Personal Tenant DNS Suffix** does not automatically change when the **GitHub Username** changes.
- Only a **Sandcastle Admin** may delete a **Personal Tenant** in v1.
- Admin tenant deletion refuses non-empty tenants unless explicitly purged.
- The admin CLI manages **Tenants** with `tenant list`, `tenant create`, `tenant status`, `tenant delete`, `tenant grant`, `tenant revoke`, and `tenant users`.
- The admin CLI manages **Users** with `user create` and `user token`; **Tenant Access** is managed with `tenant grant`, `tenant revoke`, and `tenant users`.
- Default machine storage paths include the **Project** and **Machine** names.
- Trust installation is tenant-scoped and trusts the **Tenant CA** for private machine hostnames in that **Tenant**.
- A **Project** belongs to exactly one **Tenant**.
- A **Project** has no settings beyond its name in v1.
- Admins create **Tenants**.
- Users with tenant access create named **Projects** inside that **Tenant**.
- Users with tenant access may delete named **Projects** only when they contain no **Machines**.
- The **Default Project** cannot be deleted.
- **Project** names are DNS-safe lowercase labels and may start with a digit.
- **GitHub Username Tenant Name** may start with a digit.
- Infrastructure words such as `default`, `dns`, `tailscale`, `ca`, `route`, `admin`, and `infra` are reserved **Project** names; `default` is created only by tenant creation.
- A **Project** has zero or more **Machines**.
- A **Machine** belongs to exactly one **Project**.
- A **Machine** name is unique within its **Project**.
- **Machine** names are DNS-safe lowercase labels and must not use reserved infrastructure words.
- A **Machine** has one **App Port**, defaulting to `3000`.
- A **Machine Template** is a **Machine** property, not a **Project** property.
- Machine creation defaults to the AI container **Machine Template**.
- An **Image Builder** builds **Sandcastle Images** and publishes them to the **Image Registry**; an Incus host then pulls and caches them locally for Machine creation.
- An **Image Builder** runs in its own admin-managed Incus project, separate from the **Infrastructure Project** and from any **Tenant**, and depends on no **Sandcastle Image** it produces.
- A **Sandcastle Image** changes only when an operator runs a build; there is no independent upstream that updates it.
- Machine creation starts the **Machine** and connects in an interactive terminal unless detached.
- Machine creation authorizes the User's uploaded **User SSH Public Key** for shell access.
- Machine creation waits until the **Machine** has joined the **Tenant Tailnet** and recorded its **Tailscale Machine IP** before reporting success.
- Machine connection uses **Machine SSH Access** over the Machine's **Tailscale Machine IP** as the user-facing shell path.
- Each **Machine** has a **Private Machine Proxy** that serves the machine's private hostname and forwards to its **App Port**.
- A **Machine** private hostname resolves to the Machine's **Tailscale Machine IP**.
- An **Incus Instance Name** is the bare Sandcastle machine name; because each **Project** is its own app Incus project, two projects in the same tenant can each have a machine with the same name.
- A **Container** is the default **Machine** type.
- A **VM** is a future **Machine** type.
- The user CLI manages **Machines** with `list`, `create`, `connect`, `start`, `stop`, `restart`, and `delete`.
- **Machine** is the implicit top-level resource in both user and admin CLIs.
- The user CLI manages **Projects** with `project list`, `project create`, `project status`, and `project delete`.
- The admin CLI lists **Machines** for any tenant with `list`; it has no per-machine create, connect, or delete verbs.
- `sandcastle-admin` is the canonical admin CLI.
- Admin `list` takes `tenant` for all projects or `tenant/project` for one project.
- Admin `list` uses `-u` or `--include-unmanaged` for unmanaged Incus instances; all-project scope is expressed by passing a tenant reference.
- `list` without a project lists **Machines** in the configured **Current Project** when set, otherwise across every **Project** in the current **Tenant**.
- `list project` lists only **Machines** in that **Project**.
- `list --all-projects` or `-a` overrides configured **Current Project** narrowing.
- Machine list output always includes each **Machine**'s **Project**.
- Every **Tenant** starts with exactly one **Default Project**.
- The **Default Project** follows the same project rules as any other **Project**.
- A **Machine** hostname is `machine.project.tenant`, where `tenant` is the **Tenant DNS Suffix**.
- A **Machine** gets exact and per-machine wildcard private DNS records.
- Sandcastle does not create project-wide or tenant-wide private DNS wildcards.
- A **Tenant DNS Suffix** must not be a public TLD, IANA special-use name, or admin-denied local suffix.
- **Local DNS Installation** is configured per **Tenant DNS Suffix**.
- **Tenant Metadata** is the source of truth for the tenant's project list.
- **Machine** metadata records the machine's **Project**, name, and type.
- Sandcastle metadata uses **Tenant**, **Project**, and **Machine** vocabulary, with no `owner` or `sandbox` compatibility aliases.
- Normal Sandcastle operations ignore unmanaged Incus instances.
- List commands may show unmanaged Incus instances when explicitly requested with `--include-unmanaged` or `-u`.
- `-u` only means include unmanaged Incus instances; it does not override project scoping.
- Unmanaged Incus instances are shown only in tenant-wide list output.
- Unmanaged Incus instance rows appear only when list scope is tenant-wide and unmanaged output is explicitly requested.
- Status output always reports unmanaged Incus instance counts.
- A bare machine reference in the user CLI belongs to the **Current Project**.
- If no project is supplied by CLI input, environment, or local configuration, the **Current Project** is the **Default Project**.
- The user CLI reads the **Current Tenant** from `SANDCASTLE_TENANT` or local configuration.
- Local configuration may store default tenant and project selections.
- Local **Current Tenant** selection does not mutate persisted Incus CLI project selection.
- Environment variables override local configuration.
- Shared infrastructure creation resolves input from CLI flags, environment variables, the **Infrastructure Seed File**, and built-in defaults, in that order.
- Machine creation resolves the **Current Project** from an explicit reference, `SANDCASTLE_PROJECT`, local project configuration, or the **Default Project**, in that order.
- Machine lookup commands may search across projects when no project is supplied and no `SANDCASTLE_PROJECT` is set, but only act when the machine name is unique.
- Destructive machine lookup commands require confirmation when the **Project** was inferred, unless the user supplies an explicit confirmation flag.
- A **User** may have **Tenant Access** to one or more **Tenants**.
- The Auth App may report the **Tenants** accessible to a **User** without changing the **Current Tenant**.
- User-facing tenant lists show only **Tenants** accessible to the requesting **User**.
- User-facing tenant lists show tenant identity and selection state, not diagnostic health.
- A **User** has one **Sandcastle User Key**.
- A **Sandcastle User Key** is the allowlisted **Normalized GitHub Username** in v1.
- A **GitHub Username** rename requires explicit future migration code.
- GitHub is the only external login provider in v1.
- Sandcastle v1 has no password login for the Auth App.
- **GitHub Email** may be stored but is not used for notifications in v1.
- **GitHub Email** is not used for identity, allowlisting, tenant names, or OIDC subject claims.
- Admins manage the **Login Allowlist** by entering **GitHub Usernames**.
- The **Login Allowlist** authorizes by **Normalized GitHub Username** in v1.
- The **Login Allowlist** contains explicit GitHub users only in v1, not GitHub organizations or teams.
- The Auth App verifies a **GitHub Username** with GitHub before adding it to the **Login Allowlist**.
- The **Login Allowlist** stores the numeric GitHub account ID as metadata for audit and future migration.
- A GitHub account rename blocks **GitHub OAuth Login** until a **Sandcastle Admin** performs a migration or allowlist repair.
- Adding a GitHub account to the **Login Allowlist** is enough to provision that user's **Personal Tenant** during CLI Device Login.
- Adding a GitHub account to the **Login Allowlist** does not immediately create a **Personal Tenant**.
- Removing a GitHub account from the **Login Allowlist** blocks new **GitHub OAuth Login** and **CLI Device Login**.
- Removing a GitHub account from the **Login Allowlist** revokes that User's active **Tenant Access** and restricted Incus certificate grants by default.
- Removing a GitHub account from the **Login Allowlist** does not delete the User's **Personal Tenant** or Machines.
- The Auth App creates a **Personal Tenant** lazily during the user's first successful **CLI Device Login**.
- Browser-only **GitHub OAuth Login** creates a web session but does not create a **Personal Tenant**.
- Only a **Sandcastle Admin** may manage the **Login Allowlist**.
- Only a **Sandcastle Admin** may grant or revoke **Tenant Access** through the Auth App.
- The first **Sandcastle Admin** is bootstrapped from deployment configuration.
- Initial **Sandcastle Admins** are bootstrapped from configured **GitHub Usernames**.
- The **Auth App** manages **Tenant Access** by applying the same restricted Incus certificate grants as `sandcastle-admin`.
- A **User** may authenticate to Sandcastle through **GitHub OAuth Login**.
- The **Sandcastle OIDC Provider** issues workload identity tokens for **Machines**, not browser login sessions.
- A **Per-Tenant OIDC Issuer** is scoped to exactly one **Tenant**.
- A **Workload Identity Token** issuer is the **Per-Tenant OIDC Issuer** for the token's **Tenant**.
- A **Workload Identity Token** identifies both the **User** and the **Machine**.
- A **Workload Identity Token** may expose **Tenant**, **Project**, **Machine**, **Sandcastle User Key**, **GitHub Username**, and **Cloud Identity Audience** claims.
- A **Workload Identity Token** does not use the legacy `sandbox` vocabulary.
- A **Workload Identity Token** expires after 15 minutes in v1.
- An **OIDC Signing Key** is stored encrypted in the **Auth Database**.
- An **OIDC Signing Key** belongs to one **Per-Tenant OIDC Issuer**.
- The **Sandcastle OIDC Provider** publishes public signing keys through JWKS.
- The Auth App deployment secret protects encrypted sensitive state and web sessions.
- A **Machine** uses a **Machine Runtime Secret** to request **Workload Identity Tokens**.
- A **Machine Runtime Secret** is rotated when workload identity is enabled, re-enabled, or the **Machine** is rebuilt.
- The **Auth App** stores only a verifier for a **Machine Runtime Secret**, not the raw secret.
- A **User** may define one or more **Cloud Identity Configs**.
- The `sc cloud-identity gcp setup` command configures external GCP trust for a **Tenant** and prints the values stored in a **Cloud Identity Config**.
- Enabling workload identity for a **Machine** rotates a **Machine Runtime Secret** through the **Auth App** and injects workload identity files into a **Machine** through the tenant-scoped user remote.
- **Cloud Identity Configs** are selected per **Machine** when workload identity is enabled.
- Sandcastle v1 does not apply **Cloud Identity Configs** automatically at the **Tenant** or **Project** level.
- The **Auth App** is implemented as part of the Go Sandcastle codebase.
- The **Auth App** runs as its own infrastructure service.
- The **Auth App** uses minimal server-rendered HTML for its user and admin workflows.
- The **Auth App** is served publicly at the configured **Auth Hostname**.
- The **Auth Hostname** is the issuer host for the **Sandcastle OIDC Provider**.
- The **Auth Hostname** is reserved infrastructure routing, not a user-facing resource.
- The **Auth App** stores login and device authorization state in the **Auth Database**.
- The **Auth Database** lives on persistent infrastructure storage and is scoped to a single Auth App instance in v1.
- **Tenant Metadata** remains the authoritative Sandcastle state for tenant runtime resources, not the Auth App's session or login store.
- **Tenant Metadata** is authoritative for **Tenant Tailnet** configuration.
- **CLI Device Login** returns an **Incus Certificate Add Token**, not a generated client private key.
- During **CLI Device Login**, the CLI generates and stores its own Incus client private key locally.
- During **CLI Device Login**, the CLI uploads a **User SSH Public Key** and keeps the matching private key local.
- **CLI Device Login** prefers the user's existing `id_ed25519.pub`, can use an explicit SSH public key path, and otherwise creates a local **Sandcastle SSH Key**.
- Each successful **CLI Device Login** replaces the **User SSH Public Key** when the uploaded key differs from the stored key.
- **CLI Device Login** reconciles the current **User SSH Public Key** onto existing **Machines** in the User's **Personal Tenant** before reaching **Login Readiness**.
- Users start **CLI Device Login** with `sandcastle login <auth-host>`.
- **CLI Device Login** shows Personal Tenant provisioning progress in the terminal.
- **CLI Device Login** reports provisioning progress through polling status messages in v1.
- The browser authorization page for **CLI Device Login** only confirms authorization and sends the user back to the terminal.
- **CLI Device Login** provisioning is idempotent and safe to retry after partial failure.
- **CLI Device Login** provisions Tailscale-backed **Tenant Infrastructure**, including the **Tenant Tailnet**, server-side and may offer **Local DNS Installation** client-side for hostname convenience.
- **CLI Device Login** reaches **Login Readiness** only when the User can create and connect to a **Machine**.
- **CLI Device Login** ends with a **CLI Login Result** containing the selected User, Current Tenant, Current Project, credential enrollment data, SSH key fingerprint, Tenant Tailnet status, and next command.
- **CLI Device Login** guides the user through joining the relevant **Tenant Tailnet** and verifies the **Tailscale Prerequisite** before reaching **Login Readiness**.
- **CLI Device Login** sets the current tenant only when the User has exactly one accessible **Tenant**.
- First-time **CLI Device Login** defaults the selected **Current Tenant** to the User's **Personal Tenant**.
- **CLI Device Login** joins only the selected **Current Tenant**'s **Tenant Tailnet**, not every accessible tenant tailnet.
- **CLI Device Login** may succeed for a **User** with no **Tenant Access**.
- A **User** with no **Tenant Access** cannot manage Sandcastle resources until a **Sandcastle Admin** grants access.
- A **User** receives **Tenant Access** to their **Personal Tenant** when it is created.
- **Tenant Access** grants access to every **Project** and **Machine** in that **Tenant**.
- **Tenant Access** grants management rights over **Projects** and **Machines** in that **Tenant**.
- Revoking **Tenant Access** revokes **Machine SSH Access** by removing that User's **User SSH Public Key** from Machines in that **Tenant**.
- User CLI commands operate in exactly one **Current Tenant**.
- Switching the **Current Tenant** should validate **Tenant Access** when online validation is available.
- A local-only **Current Tenant** switch is an explicit escape hatch from online **Tenant Access** validation.
- Switching the **Current Tenant** does not change the **Current Project**.
- Switching the **Current Tenant** does not perform **Local DNS Installation**, trust installation, or **Tenant Tailnet** setup.
- When a user has multiple tenants and no **Current Tenant** is selected, user CLI commands fail until the tenant is selected.
- Bare user `status` reports **Current Tenant** status.
- Admins grant and revoke **Tenant Access**, not project access.
- User deletion removes **Tenant Access** and user credentials, not tenant resources.
- **Created By** metadata does not affect authorization.
- Raw Incus access is not a supported user interface.
- A **User** is not the namespace owner; the **Tenant** is.

## Example Dialogue

> **Dev:** "When the admin creates a tenant, which project does the first container go into?"
> **Domain expert:** "Every Tenant starts with a default Project, so a container can be created before the user names a project."
>
> **Dev:** "What is the private hostname for container `codex` in tenant `acme`'s default project?"
> **Domain expert:** "`codex.default.acme`; Sandcastle keeps hostnames short and validates that `acme` does not collide with known DNS roots."

## Flagged Ambiguities

- "owner" was previously used as the top-level namespace in code and specs; resolved: the canonical domain term is **Tenant**, and **User** is only an access identity.
- "GitHub username as UID" makes Sandcastle identity mutable; resolved: accepted for v1, with future migration code needed if a GitHub account is renamed.
- "Whitelisted GitHub username" is both admin-facing input and the v1 authorization key; resolved: **Login Allowlist** entries are keyed by **GitHub Username**.
- "Admins create all tenants" is not true for allowlisted users; resolved: the Auth App creates a **Personal Tenant** during first **CLI Device Login** for each allowlisted GitHub account.
- "GitHub OpenID login" conflated GitHub browser authentication with Sandcastle workload identity; resolved: use **GitHub OAuth Login** for browser sign-in and **Sandcastle OIDC Provider** for external cloud trust.
- The older Rails app used `sandbox` in OIDC claims; resolved: Incus Sandcastle **Workload Identity Tokens** use **Tenant**, **Project**, and **Machine** vocabulary.
- "Store everything in Incus metadata" would mix login/session state with tenant runtime metadata; resolved: the **Auth App** uses an **Auth Database**, while **Tenant Metadata** remains the tenant runtime source of truth.
- "Token for Incus auth" could mean a private credential or an enrollment token; resolved: **CLI Device Login** returns an **Incus Certificate Add Token** and never exposes a client private key to the **Auth App**.
- "containers" can mean user-facing runtime environments or the Incus implementation type; resolved: use **Machine** for the product concept and **Container** only for the Incus-backed Machine type.
- "default" could mean CLI shorthand or a real project; resolved: **Default Project** is a real **Project** named `default`.
- "tenant-tld" suggested that the tenant name is a public DNS top-level domain; resolved: use **Tenant DNS Suffix** for the private final hostname label.
- A bare machine name in the CLI could imply a projectless resource; resolved: it means the machine in the **Current Project**, which defaults to the **Default Project**.
- `SANDCASTLE_OWNER` would preserve old terminology; resolved: use `SANDCASTLE_TENANT` only, with no compatibility alias.
- Existing owner/project/sandbox resources and metadata do not require backward compatibility migration.
- Older command words such as `add`, `enter`, and `rm` were considered; resolved: the canonical machine CLI verbs are `list`, `create`, `connect`, `start`, `stop`, `restart`, `status`, and `delete`.
- `inspect` was considered for detailed state; resolved: `status` is the canonical detail command.
- `docs/sandcastle-v1-spec.md` previously described the superseded owner/project model; resolved domain language now lives here, in ADR-0001, and in the rewritten v1 spec.
- "sc container" and "build machine" were used for the box that builds images; resolved: it is an **Image Builder** infrastructure appliance, not a **Machine**.
