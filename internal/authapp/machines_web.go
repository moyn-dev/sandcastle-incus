package authapp

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// machinesWeb renders a minimal, mobile-first page listing the signed-in user's
// machines across every tenant they can access, each with a tap-to-connect
// ssh:// link. The SSH target is the machine Private IP: machines have no
// distinct Tailscale address, but the tenant's Tailscale sidecar advertises the
// private subnet, so the Private IP is what a Tailscale-connected device dials.
func (h handler) machinesWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/machines" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(h.sessionCookie)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	user, err := UserForSession(r.Context(), h.db, cookie.Value, timeNow())
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	page := machinesPage{User: user, AuthHostname: h.authHostname}
	summaries, err := h.accessibleTenantSummaries(r, user)
	if err != nil {
		page.Error = err.Error()
		h.renderMachinesPage(w, page)
		return
	}
	if h.machines == nil {
		page.Error = "machine metadata store is not configured"
		h.renderMachinesPage(w, page)
		return
	}
	for _, summary := range summaries {
		machines, err := h.machines.ListMachines(r.Context(), summary)
		if err != nil {
			page.Error = fmt.Sprintf("list machines for %s: %v", summary.Tenant, err)
			h.renderMachinesPage(w, page)
			return
		}
		view := machinesTenantView{Tenant: summary.Tenant}
		for _, m := range machines {
			view.Machines = append(view.Machines, machineView{
				Project: m.Project,
				Name:    m.Name,
				FQDN:    machineWebFQDN(summary, m),
				IP:      strings.TrimSpace(m.PrivateIP),
				SSHURL:  machineSSHURL(summary, m),
				Running: m.Running,
			})
		}
		sort.Slice(view.Machines, func(i, j int) bool {
			if view.Machines[i].Project != view.Machines[j].Project {
				return view.Machines[i].Project < view.Machines[j].Project
			}
			return view.Machines[i].Name < view.Machines[j].Name
		})
		page.Total += len(view.Machines)
		page.Tenants = append(page.Tenants, view)
	}
	sort.Slice(page.Tenants, func(i, j int) bool { return page.Tenants[i].Tenant < page.Tenants[j].Tenant })
	h.renderMachinesPage(w, page)
}

func (h handler) renderMachinesPage(w http.ResponseWriter, page machinesPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = machinesTemplate.Execute(w, page)
}

// accessibleTenantSummaries returns every tenant the user is granted access to.
// Shared by the machines web UI and the /api/tenants endpoint.
func (h handler) accessibleTenantSummaries(r *http.Request, user User) ([]tenant.Summary, error) {
	if h.tenants == nil {
		return nil, fmt.Errorf("tenant store is not configured")
	}
	if h.tenantAccess == nil {
		return nil, fmt.Errorf("tenant access manager is not configured")
	}
	summaries, err := tenant.ListForPrefix(r.Context(), h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return nil, err
	}
	normalized := NormalizeGitHubUsername(user.UserKey)
	accessible := make([]tenant.Summary, 0, len(summaries))
	for _, summary := range summaries {
		// A Personal Tenant belongs to the user whose key names it; a Shared
		// Tenant admits its Tenant Members (Tenant Metadata, KeyV2Members).
		if summary.Accessible(normalized) {
			accessible = append(accessible, summary)
		}
	}
	return accessible, nil
}

// machineSSHUser resolves the SSH login (user@host): the explicit machine Linux
// user, else the tenant's Unix login user. For v2 tenants that is the profile
// login user (from the infra project's KeyV2User, surfaced as summary.UnixUser);
// if it is somehow absent, fall back to the v2 default login user — never the
// tenant name, which is not a Unix account on the machine. v1 keeps the tenant
// name as its last-resort user.
func machineSSHUser(summary tenant.Summary, m meta.Machine) string {
	if u := strings.TrimSpace(m.LinuxUser); u != "" {
		return u
	}
	if u := strings.TrimSpace(summary.UnixUser); u != "" {
		return u
	}
	return tenant.DefaultV2UnixUser
}

func machineWebFQDN(summary tenant.Summary, m meta.Machine) string {
	suffix := strings.Trim(strings.TrimSpace(summary.DNSSuffix), ".")
	if suffix == "" {
		suffix = strings.Trim(strings.TrimSpace(summary.Tenant), ".")
	}
	if m.Name == "" || m.Project == "" || suffix == "" {
		return ""
	}
	return m.Name + "." + m.Project + "." + suffix
}

// machineSSHURL builds the ssh://user@ip target, or empty when the IP is unknown.
// The result is trusted (derived from tenant/machine metadata, not user input),
// so it is marked template.URL to survive html/template's scheme filtering.
func machineSSHURL(summary tenant.Summary, m meta.Machine) template.URL {
	ip := strings.TrimSpace(m.PrivateIP)
	if ip == "" {
		return ""
	}
	user := machineSSHUser(summary, m)
	if user == "" {
		return template.URL("ssh://" + ip)
	}
	return template.URL("ssh://" + user + "@" + ip)
}

type machinesPage struct {
	User         User
	AuthHostname string
	Tenants      []machinesTenantView
	Total        int
	Error        string
}

type machinesTenantView struct {
	Tenant   string
	Machines []machineView
}

type machineView struct {
	Project string
	Name    string
	FQDN    string
	IP      string
	SSHURL  template.URL
	Running bool
}

var machinesTemplate = template.Must(template.New("machines").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Your Sandcastle machines</title>
  <style>
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f7;
      color: #1d1d1f;
    }
    @media (prefers-color-scheme: dark) {
      body { background: #000; color: #f5f5f7; }
      .card { background: #1c1c1e; }
      .meta { color: #a1a1a6; }
    }
    header {
      padding: 16px;
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
    }
    h1 { font-size: 20px; margin: 0; }
    .who { font-size: 13px; opacity: 0.7; }
    main { padding: 0 12px 32px; max-width: 640px; margin: 0 auto; }
    h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.6; margin: 24px 8px 8px; }
    .card {
      background: #fff;
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 10px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.08);
    }
    .name { font-size: 17px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: #c7c7cc; }
    .dot.up { background: #34c759; }
    .meta { font-size: 13px; color: #6e6e73; margin-top: 2px; word-break: break-all; }
    .ssh {
      display: block;
      margin-top: 12px;
      padding: 11px 14px;
      border-radius: 10px;
      background: #0071e3;
      color: #fff;
      text-decoration: none;
      text-align: center;
      font-weight: 600;
    }
    .ssh.disabled { background: #c7c7cc; pointer-events: none; }
    .empty { text-align: center; opacity: 0.6; margin-top: 48px; }
    .nav { font-size: 13px; margin: 8px; }
    .nav a { color: #0071e3; text-decoration: none; }
    .error { background: #ffe5e5; color: #8a1f1f; border-radius: 10px; padding: 12px 14px; margin: 12px 8px; }
    @media (prefers-color-scheme: dark) { .error { background: #3a1212; color: #ff9d9d; } }
  </style>
</head>
<body>
  <header>
    <h1>Your machines</h1>
    <span class="who">{{.User.GitHubUsername}}</span>
  </header>
  <main>
    <p class="nav"><a href="/">Home</a> · <a href="/logs">Activity log</a></p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    {{if not .Total}}
      {{if not .Error}}<p class="empty">No machines yet.</p>{{end}}
    {{else}}
      {{range .Tenants}}
        {{if .Machines}}
          <h2>{{.Tenant}}</h2>
          {{range .Machines}}
            <div class="card">
              <div class="name"><span class="dot {{if .Running}}up{{end}}"></span>{{.Name}}</div>
              <div class="meta">project: {{.Project}}</div>
              {{if .FQDN}}<div class="meta">{{.FQDN}}</div>{{end}}
              <div class="meta">ip: {{if .IP}}{{.IP}}{{else}}—{{end}}</div>
              {{if .SSHURL}}
                <a class="ssh" href="{{.SSHURL}}">SSH to {{.Name}}</a>
              {{else}}
                <span class="ssh disabled">No IP — cannot connect</span>
              {{end}}
            </div>
          {{end}}
        {{end}}
      {{end}}
    {{end}}
  </main>
</body>
</html>
`))
