package authapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/svclog"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
	DeviceStatusExpired  = "expired"

	deviceLoginTTL      = 10 * time.Minute
	devicePollInterval  = 2
	deviceUserCodeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

type DeviceLogin struct {
	DeviceCode    string
	UserCode      string
	Status        string
	UserKey       string
	Message       string
	ProvisionedAt string
	Token         string
	RemoteName    string
	// RequestedDNSSuffix is the Tenant DNS Suffix the user typed into the browser
	// approval form (ADR-0020). It is persisted at approval and used for
	// first-login provisioning unless the CLI --dns-suffix flag overrides it.
	RequestedDNSSuffix string
	// RequestedInitialProject is the initial-project short name the user typed
	// into the browser approval form (issue #93). Persisted at approval; used for
	// first-login provisioning unless the CLI --default-project flag overrides it.
	RequestedInitialProject string
	// DNSSuffix is the resolved suffix returned after provisioning.
	DNSSuffix string
	// CurrentProject is the resolved short name of the tenant's project after
	// provisioning (issue #93) — what the CLI pins as its current project.
	CurrentProject     string
	IncusRemoteAddress string
	IncusProject       string
	TailscaleLoginURL  string
	TenantPrivateCIDR  string
	AccessibleTenants  []string
	Projects           []string
	VerificationURI    string
	ExpiresAt          time.Time
	Interval           int
}

type deviceStartResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Status          string `json:"status"`
	Message         string `json:"message"`
}

type devicePollResponse struct {
	Status             string          `json:"status"`
	Message            string          `json:"message"`
	UserKey            string          `json:"user_key,omitempty"`
	CLIAuthToken       string          `json:"cli_auth_token,omitempty"`
	Token              string          `json:"incus_certificate_add_token,omitempty"`
	RemoteName         string          `json:"remote_name,omitempty"`
	DNSSuffix          string          `json:"dns_suffix,omitempty"`
	IncusRemoteAddress string          `json:"incus_remote_address,omitempty"`
	IncusProject       string          `json:"incus_project,omitempty"`
	TailscaleLoginURL  string          `json:"tailscale_login_url,omitempty"`
	TenantPrivateCIDR  string          `json:"tenant_private_cidr,omitempty"`
	AccessibleTenants  []string        `json:"accessible_tenants,omitempty"`
	Projects           []string        `json:"projects,omitempty"`
	CurrentTenant      string          `json:"current_tenant,omitempty"`
	CurrentProject     string          `json:"current_project,omitempty"`
	SSHKeyFingerprint  string          `json:"ssh_key_fingerprint,omitempty"`
	TenantTailnetState string          `json:"tenant_tailnet_state,omitempty"`
	TailscaleAuthKey   string          `json:"tailscale_auth_key,omitempty"`
	NextCommand        string          `json:"next_command,omitempty"`
	LoginResult        *CLILoginResult `json:"login_result,omitempty"`
	ExpiresIn          int             `json:"expires_in,omitempty"`
	// Warning carries a non-fatal problem the client should show the user
	// (e.g. the SSH key could not be written to every existing machine).
	Warning string `json:"warning,omitempty"`
}

func (h handler) deviceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	login, err := CreateDeviceLogin(r.Context(), h.db, h.authHostname, timeNow())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, deviceStartResponse{
		DeviceCode:      login.DeviceCode,
		UserCode:        login.UserCode,
		VerificationURI: login.VerificationURI,
		ExpiresIn:       int(time.Until(login.ExpiresAt).Seconds()),
		Interval:        login.Interval,
		Status:          login.Status,
		Message:         login.Message,
	})
}

func (h handler) devicePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		DeviceCode       string `json:"device_code"`
		SSHPublicKey     string `json:"ssh_public_key"`
		LocalUnixUser    string `json:"local_unix_user"`
		TailscaleAuthKey string `json:"tailscale_auth_key"`
		// AwaitingTailnet is set by a client that already holds an enrollment
		// token but no sidecar tailnet address (BYO interactive join): the
		// server re-runs the idempotent provisioning so the sidecar's join is
		// noticed and the Incus Reach completed.
		AwaitingTailnet bool `json:"awaiting_tailnet"`
		// DNSSuffix is the tenant-chosen Tenant DNS Suffix for first-login
		// provisioning (ADR-0018).
		DNSSuffix string `json:"dns_suffix"`
		// InitialProject is the tenant-chosen initial-project short name for
		// first-login provisioning (issue #93).
		InitialProject string `json:"initial_project"`
		// ClientCertificate is the client's existing shared-identity Incus
		// certificate PEM (multi-install trust union).
		ClientCertificate string `json:"client_certificate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	login, err := PollDeviceLogin(r.Context(), h.db, request.DeviceCode, timeNow())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if login.Status == DeviceStatusApproved && h.provisioner != nil && (login.ProvisionedAt == "" || request.AwaitingTailnet) {
		// Provision on a DETACHED context, not r.Context(): tenant bring-up
		// (image pull, package install, tailscale up) takes minutes, and a client
		// poll through a flaky edge (Cloudflare tunnel) may time out and cancel
		// the request long before that — which used to abort provisioning
		// mid-flight so it never finished. A per-device lock keeps one provision
		// running at a time.
		//
		// The request must ALSO not block for the whole provision: a Cloudflare
		// tunnel gives the origin ~100s before it answers the client 524, and a
		// second tenant on a warm host measured 142s. So wait only a bounded
		// time for the work; if it is still running, answer "pending" and let the
		// client poll again (it already reports "server is provisioning"). Fast
		// provisions — every unit test, and a first tenant on a quiet host —
		// finish inside the window and behave exactly as before.
		if unlock, started := tryLockDeviceProvisioning(request.DeviceCode); started {
			provisionCtx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			// Name the user now (the login is approved) and carry the request's
			// log record onto provisionCtx, so the verbose per-phase provisioning
			// lines emitted deep in tenant bring-up are attributed to this user
			// and show at /logs alongside the span. The span runs on provisionCtx
			// because r.Context() dies with the request.
			svclog.SetUser(r.Context(), login.UserKey)
			provisionCtx = svclog.WithRecord(r.Context(), provisionCtx)
			pending := login
			done := make(chan deviceProvisionOutcome, 1)
			go func() {
				defer cancel()
				defer unlock()
				outcome := deviceProvisionOutcome{login: pending}
				outcome.err = svclog.Span(provisionCtx, "provision.personal_tenant", func() error {
					var provErr error
					outcome.login, provErr = h.provisionPersonalTenant(provisionCtx, pending, request.LocalUnixUser, request.SSHPublicKey, request.TailscaleAuthKey, effectiveDNSSuffix(request.DNSSuffix, pending.RequestedDNSSuffix), effectiveInitialProject(request.InitialProject, pending.RequestedInitialProject), request.ClientCertificate)
					return provErr
				})
				if outcome.err == nil {
					// Hand the token/remote/project to whichever poll collects it.
					storeDeviceProvisionResult(outcome.login)
				}
				if outcome.err != nil && tenant.IsTerminalProvisionError(outcome.err) {
					forgetDeviceProvisionResult(outcome.login.DeviceCode)
					// No retry can fix this (e.g. immutable-suffix conflict) —
					// deny the login so the client fails fast with the message
					// instead of polling to timeout while every poll re-attempts
					// a provisioning that can never succeed. Recorded here, not
					// in the handler, because the request may already be gone.
					_, _ = h.db.ExecContext(provisionCtx, "UPDATE device_logins SET status = ?, message = ? WHERE device_code = ?", DeviceStatusDenied, outcome.login.Message, outcome.login.DeviceCode)
				}
				done <- outcome
			}()
			select {
			case outcome := <-done:
				login, err = outcome.login, outcome.err
				if err != nil {
					if tenant.IsTerminalProvisionError(err) {
						login.Status = DeviceStatusDenied
					} else {
						login.Status = DeviceStatusPending
					}
				}
			case <-time.After(devicePollProvisionWait):
				login = provisioningInFlight(login)
			}
		} else {
			// Another poll is already provisioning this device code.
			login = provisioningInFlight(login)
		}
	}
	// A background provision started by an EARLIER poll may have finished since.
	// Its result (token, remote name, project, CIDR) lives only in memory, so
	// pick it up here — otherwise this poll would report "approved" with no
	// enrollment token and the client could not add its Incus remote.
	if login.Status == DeviceStatusApproved && strings.TrimSpace(login.Token) == "" {
		if provisioned, ok := deviceProvisionResult(request.DeviceCode); ok {
			provisioned.Status = login.Status
			provisioned.ExpiresAt = login.ExpiresAt
			login = provisioned
		}
	}
	if login.Status == DeviceStatusApproved && login.UserKey != "" && strings.TrimSpace(request.ClientCertificate) != "" {
		// Best-effort: record the client's shared-identity certificate so the
		// tenant plane can later extend its trust entry by fingerprint (the
		// entry may be named after another tenant's enrollment). A failure
		// here must not fail the login — provisioning still receives the PEM
		// transiently with this request.
		_ = SetUserClientCertificate(r.Context(), h.db, login.UserKey, request.ClientCertificate)
	}
	sshFingerprint := ""
	warning := ""
	if login.Status == DeviceStatusApproved && strings.TrimSpace(request.SSHPublicKey) != "" {
		stored, _, err := SetUserSSHKey(r.Context(), h.db, login.UserKey, request.SSHPublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Best-effort: the key is stored and lands on machines created from now
		// on; failing to rewrite authorized_keys on some EXISTING machine (e.g.
		// one built from a non-Sandcastle image with no tenant Unix user) must
		// not block enrolling this device — the user is locked out of that one
		// machine either way. Surface it as a warning instead of failing login.
		if err := h.reconcilePersonalTenantSSHKey(r.Context(), login.UserKey, stored.PublicKey); err != nil {
			warning = fmt.Sprintf("SSH key was saved but not written to every existing machine: %v", err)
			svclog.Logf(r.Context(), "device poll: %s", warning)
		}
		// Shared Tenants the user is a member of authorize this key too.
		if err := h.reconcileMemberSSHKeys(r.Context(), login.UserKey, stored.PublicKey); err != nil {
			svclog.Logf(r.Context(), "shared tenant key reconcile for %s: %v", login.UserKey, err)
		}
		sshFingerprint = stored.Fingerprint
	} else if login.Status == DeviceStatusApproved && login.UserKey != "" {
		if stored, err := GetUserSSHKey(r.Context(), h.db, login.UserKey); err == nil {
			sshFingerprint = stored.Fingerprint
		}
	}
	expiresIn := int(time.Until(login.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	loginResult := loginResultForDeviceLogin(login, sshFingerprint)
	cliAuthToken := ""
	if login.Status == DeviceStatusApproved && login.UserKey != "" {
		cliAuthToken, err = CreateCLIToken(r.Context(), h.db, login.UserKey, timeNow())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, devicePollResponse{
		Status:             login.Status,
		Message:            login.Message,
		UserKey:            login.UserKey,
		CLIAuthToken:       cliAuthToken,
		Token:              login.Token,
		RemoteName:         login.RemoteName,
		DNSSuffix:          login.DNSSuffix,
		IncusRemoteAddress: login.IncusRemoteAddress,
		IncusProject:       login.IncusProject,
		TailscaleLoginURL:  login.TailscaleLoginURL,
		TenantPrivateCIDR:  login.TenantPrivateCIDR,
		AccessibleTenants:  login.AccessibleTenants,
		Projects:           login.Projects,
		CurrentTenant:      currentTenantForDeviceLogin(login),
		CurrentProject:     currentProjectForDeviceLogin(login),
		SSHKeyFingerprint:  sshFingerprint,
		TenantTailnetState: tenantTailnetStateForDeviceLogin(login),
		TailscaleAuthKey:   h.tailscaleAuthKeyForDeviceLogin(login),
		NextCommand:        nextCommandForDeviceLogin(login),
		LoginResult:        loginResult,
		ExpiresIn:          expiresIn,
		Warning:            warning,
	})
}

// cliFlagOrBrowserForm resolves a first-login provisioning input supplied by two
// paths: the CLI flag (cli) wins when non-blank, otherwise the browser
// approval-form value (browser). Both are trimmed; "" means "let provisioning
// default it".
func cliFlagOrBrowserForm(cli, browser string) string {
	if s := strings.TrimSpace(cli); s != "" {
		return s
	}
	return strings.TrimSpace(browser)
}

// effectiveDNSSuffix resolves the Tenant DNS Suffix for provisioning: the CLI
// --dns-suffix flag wins over the browser approval form's value. Empty means
// "let the server default it" (tenant name).
func effectiveDNSSuffix(cli, browser string) string { return cliFlagOrBrowserForm(cli, browser) }

// effectiveInitialProject resolves the initial-project short name for first-login
// provisioning (issue #93): the CLI --default-project flag wins over the browser
// approval form's value. Empty means "let provisioning default it" (the stored
// name on re-login, else "default").
func effectiveInitialProject(cli, browser string) string {
	return cliFlagOrBrowserForm(cli, browser)
}

func (h handler) tailscaleAuthKeyForDeviceLogin(login DeviceLogin) string {
	if login.Status != DeviceStatusApproved {
		return ""
	}
	return strings.TrimSpace(h.tailscaleAuthKey)
}

func (h handler) reconcilePersonalTenantSSHKey(ctx context.Context, userKey string, publicKey string) error {
	if h.machineSSHKeys == nil {
		return nil
	}
	if h.tenants == nil {
		return fmt.Errorf("cannot reconcile User SSH Public Key: tenant store is not configured")
	}
	summaries, err := tenant.ListForPrefix(ctx, h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return fmt.Errorf("list tenants for User SSH Public Key reconciliation: %w", err)
	}
	tenantName := NormalizeGitHubUsername(userKey)
	for _, summary := range summaries {
		if summary.Tenant == tenantName {
			// Both versions reconcile. A v2 tenant's default-project profile is
			// refreshed by provisioning, but that only reaches machines created
			// AFTERWARDS — every machine that already existed keeps the old key
			// baked in by cloud-init and rejects the rotated one. The reconciler
			// resolves v2 instance names and per-project Incus projects itself.
			if err := h.machineSSHKeys.ReconcileUserSSHKey(ctx, summary, tenantName, publicKey); err != nil {
				return fmt.Errorf("reconcile User SSH Public Key for Personal Tenant %s: %w", tenantName, err)
			}
			return nil
		}
	}
	return nil
}

func (h handler) findPersonalTenant(ctx context.Context, userKey string) (tenant.Summary, error) {
	summaries, err := tenant.ListForPrefix(ctx, h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return tenant.Summary{}, err
	}
	tenantName := NormalizeGitHubUsername(userKey)
	for _, summary := range summaries {
		if summary.Tenant == tenantName {
			return summary, nil
		}
	}
	return tenant.Summary{}, fmt.Errorf("Personal Tenant %s not found", tenantName)
}

type CLILoginResult struct {
	SelectedUser         string               `json:"selected_user"`
	CurrentTenant        string               `json:"current_tenant,omitempty"`
	CurrentProject       string               `json:"current_project,omitempty"`
	CredentialEnrollment CredentialEnrollment `json:"credential_enrollment"`
	SSHKeyFingerprint    string               `json:"ssh_key_fingerprint,omitempty"`
	TenantTailnetStatus  TenantTailnetStatus  `json:"tenant_tailnet_status"`
	AccessibleTenants    []string             `json:"accessible_tenants,omitempty"`
	Projects             []string             `json:"projects,omitempty"`
	Message              string               `json:"message"`
	NextCommand          string               `json:"next_command,omitempty"`
}

type CredentialEnrollment struct {
	IncusCertificateAddToken string `json:"incus_certificate_add_token,omitempty"`
	RemoteName               string `json:"remote_name,omitempty"`
	IncusRemoteAddress       string `json:"incus_remote_address,omitempty"`
}

type TenantTailnetStatus struct {
	State   string `json:"state,omitempty"`
	Tailnet string `json:"tailnet,omitempty"`
}

func loginResultForDeviceLogin(login DeviceLogin, sshFingerprint string) *CLILoginResult {
	if login.Status != DeviceStatusApproved {
		return nil
	}
	return &CLILoginResult{
		SelectedUser:   login.UserKey,
		CurrentTenant:  currentTenantForDeviceLogin(login),
		CurrentProject: currentProjectForDeviceLogin(login),
		CredentialEnrollment: CredentialEnrollment{
			IncusCertificateAddToken: login.Token,
			RemoteName:               login.RemoteName,
			IncusRemoteAddress:       login.IncusRemoteAddress,
		},
		SSHKeyFingerprint: sshFingerprint,
		TenantTailnetStatus: TenantTailnetStatus{
			State:   tenantTailnetStateForDeviceLogin(login),
			Tailnet: tenantTailnetForDeviceLogin(login),
		},
		AccessibleTenants: append([]string{}, login.AccessibleTenants...),
		Projects:          append([]string{}, login.Projects...),
		Message:           login.Message,
		NextCommand:       nextCommandForDeviceLogin(login),
	}
}

func currentTenantForDeviceLogin(login DeviceLogin) string {
	if len(login.AccessibleTenants) == 1 {
		return login.AccessibleTenants[0]
	}
	return ""
}

func currentProjectForDeviceLogin(login DeviceLogin) string {
	if login.Status == DeviceStatusApproved && currentTenantForDeviceLogin(login) != "" {
		// The tenant's one project — the user-chosen short name once provisioning
		// has resolved it (issue #93), else the "default" fallback (e.g. an
		// approved login whose provisioning result hasn't landed yet).
		if project := strings.TrimSpace(login.CurrentProject); project != "" {
			return project
		}
		return "default"
	}
	return ""
}

func tenantTailnetStateForDeviceLogin(login DeviceLogin) string {
	if login.Status == DeviceStatusApproved {
		return "pending"
	}
	return ""
}

func tenantTailnetForDeviceLogin(login DeviceLogin) string {
	return ""
}

func nextCommandForDeviceLogin(login DeviceLogin) string {
	if login.Status == DeviceStatusApproved && currentTenantForDeviceLogin(login) != "" {
		return "sandcastle create dev"
	}
	return ""
}

func (h handler) provisionPersonalTenant(ctx context.Context, login DeviceLogin, localUnixUser string, sshPublicKey string, tailscaleAuthKey string, dnsSuffix string, initialProject string, clientCertificatePEM string) (DeviceLogin, error) {
	user, err := FindUser(ctx, h.db, login.UserKey)
	if err != nil {
		return DeviceLogin{}, err
	}
	user.LocalUnixUser = strings.TrimSpace(localUnixUser)
	user.SSHPublicKey = strings.TrimSpace(sshPublicKey)
	if _, err := h.db.ExecContext(ctx, "UPDATE device_logins SET message = ? WHERE device_code = ? AND provisioned_at = ''", "Provisioning Personal Tenant for "+user.UserKey+".", login.DeviceCode); err != nil {
		return DeviceLogin{}, err
	}
	result, err := h.provisioner.EnsurePersonalTenant(ctx, user, ProvisionOptions{TailscaleAuthKey: tailscaleAuthKey, DNSSuffix: dnsSuffix, InitialProject: initialProject, ClientCertificatePEM: clientCertificatePEM})
	if err != nil {
		message := "Personal Tenant provisioning failed: " + err.Error()
		_, _ = h.db.ExecContext(ctx, "UPDATE device_logins SET message = ? WHERE device_code = ? AND provisioned_at = ''", message, login.DeviceCode)
		login.Message = message
		return login, err
	}
	message := result.normalizedMessage()
	_, err = h.db.ExecContext(ctx, "UPDATE device_logins SET message = ?, provisioned_at = ? WHERE device_code = ?", message, timeNow().UTC().Format(time.RFC3339), login.DeviceCode)
	if err != nil {
		return DeviceLogin{}, err
	}
	login, err = findDeviceLoginByDeviceCode(ctx, h.db, login.DeviceCode)
	if err != nil {
		return DeviceLogin{}, err
	}
	login.Token = result.Token
	login.RemoteName = result.RemoteName
	login.DNSSuffix = result.DNSSuffix
	login.CurrentProject = result.CurrentProject
	login.IncusRemoteAddress = result.IncusRemoteAddress
	login.IncusProject = result.IncusProject
	login.TailscaleLoginURL = result.TailscaleLoginURL
	login.TenantPrivateCIDR = result.TenantPrivateCIDR
	login.AccessibleTenants = append([]string{}, result.AccessibleTenants...)
	login.Projects = append([]string{}, result.Projects...)
	return login, nil
}

func (h handler) deviceApprove(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.deviceApproveForm(w, r)
	case http.MethodPost:
		h.deviceApprovePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// deviceFormData drives the device-approval template. The DNS-suffix and
// initial-project inputs are first-login-only: once the tenant exists both are
// fixed (the suffix is immutable, the project already created), so we hide the
// inputs and instead show what is already there.
type deviceFormData struct {
	UserCode         string
	ShowSuffixInput  bool
	DNSSuffix        string // prefill for the input (first login only)
	ExistingSuffix   string // shown read-only once the tenant exists
	ShowProjectInput bool
	InitialProject   string // prefill for the input (first login only)
	ExistingProjects []string
}

func (h handler) deviceApproveForm(w http.ResponseWriter, r *http.Request) {
	user, err := h.requireAllowlistedSession(r)
	if err != nil {
		// Come back HERE (with the user_code) after the GitHub login —
		// otherwise the user lands on the start page and the code is lost.
		http.Redirect(w, r, "/login/github?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	data := deviceFormData{
		UserCode:         strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code"))),
		DNSSuffix:        strings.TrimSpace(r.URL.Query().Get("dns_suffix")),
		InitialProject:   strings.TrimSpace(r.URL.Query().Get("initial_project")),
		ShowSuffixInput:  true,
		ShowProjectInput: true,
	}
	// If the user already has a Personal Tenant, its DNS suffix is immutable and
	// its projects exist — don't ask to (re)name them. Show them instead. Best
	// effort: if the lookup fails (Incus unreachable / no store), fall back to
	// the inputs; leaving them blank on re-login reuses the stored values anyway.
	if h.tenants != nil {
		if summary, err := h.findPersonalTenant(r.Context(), user.UserKey); err == nil {
			if suffix := strings.TrimSpace(summary.DNSSuffix); suffix != "" {
				data.ExistingSuffix = suffix
				data.ShowSuffixInput = false
			}
			for _, p := range summary.Projects {
				if name := strings.TrimSpace(p.Name); name != "" {
					data.ExistingProjects = append(data.ExistingProjects, name)
				}
			}
			if len(data.ExistingProjects) > 0 {
				data.ShowProjectInput = false
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceTemplate.Execute(w, data)
}

func (h handler) deviceApprovePost(w http.ResponseWriter, r *http.Request) {
	user, err := h.requireAllowlistedSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(r.FormValue("user_code")))
	dnsSuffix := strings.TrimSpace(r.FormValue("dns_suffix"))
	initialProject := strings.TrimSpace(r.FormValue("initial_project"))
	action := strings.TrimSpace(r.FormValue("action"))
	switch action {
	case "approve":
		err = ApproveDeviceLogin(r.Context(), h.db, code, user.UserKey, dnsSuffix, initialProject, timeNow())
	case "deny":
		err = DenyDeviceLogin(r.Context(), h.db, code, timeNow())
	default:
		err = fmt.Errorf("device login action is required")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch action {
	case "approve":
		_, _ = w.Write([]byte("Device login approved. Return to the terminal to continue provisioning.\n"))
	case "deny":
		_, _ = w.Write([]byte("Device login denied. Return to the terminal.\n"))
	}
}

func (h handler) debugDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := FindLoginUser(r.Context(), h.db, h.debugDeviceUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !user.Allowlisted {
		http.Error(w, "debug device user must be allowlisted", http.StatusForbidden)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(r.FormValue("user_code")))
	if code == "" {
		code = strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))
	}
	if err := ApproveDeviceLogin(r.Context(), h.db, code, user.UserKey, "", "", timeNow()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "Debug-approved device login for %s.\n", user.UserKey)
}

func (h handler) requireAllowlistedSession(r *http.Request) (User, error) {
	cookie, err := r.Cookie(h.sessionCookie)
	if err != nil {
		return User{}, fmt.Errorf("web session is required")
	}
	user, err := UserForSession(r.Context(), h.db, cookie.Value, timeNow())
	if err != nil {
		return User{}, err
	}
	if !user.Allowlisted {
		return User{}, fmt.Errorf("allowlisted GitHub login is required")
	}
	svclog.SetUser(r.Context(), user.UserKey)
	return user, nil
}

func CreateDeviceLogin(ctx context.Context, db *sql.DB, authHostname string, now time.Time) (DeviceLogin, error) {
	deviceCode, err := randomToken(32)
	if err != nil {
		return DeviceLogin{}, err
	}
	userCode := newUserCode()
	expiresAt := now.Add(deviceLoginTTL).UTC()
	message := "Waiting for browser approval."
	_, err = db.ExecContext(ctx, `
INSERT INTO device_logins (device_code, user_code, status, message, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
`, deviceCode, userCode, DeviceStatusPending, message, now.UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	if err != nil {
		return DeviceLogin{}, fmt.Errorf("create device login: %w", err)
	}
	return DeviceLogin{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		Status:          DeviceStatusPending,
		Message:         message,
		VerificationURI: verificationURI(authHostname, userCode),
		ExpiresAt:       expiresAt,
		Interval:        devicePollInterval,
	}, nil
}

func PollDeviceLogin(ctx context.Context, db *sql.DB, deviceCode string, now time.Time) (DeviceLogin, error) {
	login, err := findDeviceLoginByDeviceCode(ctx, db, deviceCode)
	if err != nil {
		return DeviceLogin{}, err
	}
	if login.Status == DeviceStatusPending && !now.Before(login.ExpiresAt) {
		if _, err := db.ExecContext(ctx, "UPDATE device_logins SET status = ?, message = ? WHERE device_code = ?", DeviceStatusExpired, "Device login expired.", login.DeviceCode); err != nil {
			return DeviceLogin{}, err
		}
		login.Status = DeviceStatusExpired
		login.Message = "Device login expired."
	}
	return login, nil
}

// ApproveDeviceLogin marks a pending device login approved for userKey. dnsSuffix
// is the optional browser-chosen Tenant DNS Suffix (ADR-0020) and initialProject
// the optional browser-chosen initial-project short name (issue #93); both are
// persisted so first-login provisioning can use them when the corresponding CLI
// flag is absent.
func ApproveDeviceLogin(ctx context.Context, db *sql.DB, userCode string, userKey string, dnsSuffix string, initialProject string, now time.Time) error {
	login, err := findDeviceLoginByUserCode(ctx, db, userCode)
	if err != nil {
		return err
	}
	if login.Status != DeviceStatusPending {
		return fmt.Errorf("device login is %s", login.Status)
	}
	if !now.Before(login.ExpiresAt) {
		_, _ = db.ExecContext(ctx, "UPDATE device_logins SET status = ?, message = ? WHERE user_code = ?", DeviceStatusExpired, "Device login expired.", login.UserCode)
		return fmt.Errorf("device login expired")
	}
	_, err = db.ExecContext(ctx, `
UPDATE device_logins
SET status = ?, user_key = ?, message = ?, approved_at = ?, dns_suffix = ?, initial_project = ?
WHERE user_code = ?
`, DeviceStatusApproved, userKey, "Approved. Provisioning will continue in the CLI.", now.UTC().Format(time.RFC3339), strings.TrimSpace(dnsSuffix), strings.TrimSpace(initialProject), login.UserCode)
	return err
}

func DenyDeviceLogin(ctx context.Context, db *sql.DB, userCode string, now time.Time) error {
	login, err := findDeviceLoginByUserCode(ctx, db, userCode)
	if err != nil {
		return err
	}
	if login.Status != DeviceStatusPending {
		return fmt.Errorf("device login is %s", login.Status)
	}
	_, err = db.ExecContext(ctx, "UPDATE device_logins SET status = ?, message = ?, approved_at = ? WHERE user_code = ?", DeviceStatusDenied, "Device login denied.", now.UTC().Format(time.RFC3339), login.UserCode)
	return err
}

func findDeviceLoginByDeviceCode(ctx context.Context, db *sql.DB, deviceCode string) (DeviceLogin, error) {
	row := db.QueryRowContext(ctx, `
SELECT device_code, user_code, status, user_key, message, provisioned_at, dns_suffix, initial_project, expires_at
FROM device_logins
WHERE device_code = ?
`, strings.TrimSpace(deviceCode))
	return scanDeviceLogin(row)
}

func findDeviceLoginByUserCode(ctx context.Context, db *sql.DB, userCode string) (DeviceLogin, error) {
	row := db.QueryRowContext(ctx, `
SELECT device_code, user_code, status, user_key, message, provisioned_at, dns_suffix, initial_project, expires_at
FROM device_logins
WHERE user_code = ?
`, strings.ToUpper(strings.TrimSpace(userCode)))
	return scanDeviceLogin(row)
}

func scanDeviceLogin(row *sql.Row) (DeviceLogin, error) {
	var login DeviceLogin
	var expiresAt string
	if err := row.Scan(&login.DeviceCode, &login.UserCode, &login.Status, &login.UserKey, &login.Message, &login.ProvisionedAt, &login.RequestedDNSSuffix, &login.RequestedInitialProject, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return DeviceLogin{}, fmt.Errorf("device login not found")
		}
		return DeviceLogin{}, err
	}
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return DeviceLogin{}, err
	}
	login.ExpiresAt = parsed
	login.Interval = devicePollInterval
	return login, nil
}

func verificationURI(authHostname string, userCode string) string {
	host := strings.Trim(strings.TrimSpace(authHostname), ".")
	if host == "" {
		return "/device?user_code=" + userCode
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/") + "/device?user_code=" + userCode
	}
	return "https://" + host + "/device?user_code=" + userCode
}

func newUserCode() string {
	var builder strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			builder.WriteByte('-')
		}
		builder.WriteByte(deviceUserCodeChars[rand.Intn(len(deviceUserCodeChars))])
	}
	return builder.String()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var deviceTemplate = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/style.css">
  <title>Sandcastle Device Login</title>
</head>
<body>
  <main>
    <h1>Device Login</h1>
    <form method="post" action="/device">
      <p><label>User Code <input name="user_code" value="{{.UserCode}}"></label></p>
      {{if .ShowSuffixInput}}
      <p>
        <label>DNS suffix (TLD)
          <input name="dns_suffix" value="{{.DNSSuffix}}" placeholder="your tenant name" autocapitalize="off" autocorrect="off" spellcheck="false">
        </label><br>
        <small>Only used on your first login. It becomes the final part of your machine
        hostnames (<code>machine.project.&lt;suffix&gt;</code>) and is immutable once set.
        Leave blank to use your tenant name, or to keep your existing suffix on re-login.</small>
      </p>
      {{else}}
      <p>DNS suffix: <code>{{.ExistingSuffix}}</code><br>
        <small>Already set for your tenant, and immutable — your machine hostnames end in
        <code>.{{.ExistingSuffix}}</code>.</small>
      </p>
      {{end}}
      {{if .ShowProjectInput}}
      <p>
        <label>Initial project
          <input name="initial_project" value="{{.InitialProject}}" placeholder="default" autocapitalize="off" autocorrect="off" spellcheck="false">
        </label><br>
        <small>Only used on your first login. Names your tenant's first project — the
        middle part of your machine hostnames (<code>machine.&lt;project&gt;.suffix</code>)
        and your enrolled Incus remote. Leave blank for <code>default</code>.</small>
      </p>
      {{else}}
      <p>Projects: {{range .ExistingProjects}}<code>{{.}}</code> {{end}}<br>
        <small>Your tenant's existing projects — create more later with
        <code>sc project create &lt;name&gt;</code>.</small>
      </p>
      {{end}}
      <button name="action" value="approve" type="submit">Approve</button>
      <button name="action" value="deny" type="submit">Deny</button>
    </form>
  </main>
</body>
</html>
`))

// deviceProvisioningLocks serializes provisioning per device code so the
// concurrent polls that arrive while a (detached, minutes-long) provisioning
// is still running don't run it a second time in parallel.
var (
	deviceProvisioningMu    sync.Mutex
	deviceProvisioningLocks = map[string]*sync.Mutex{}
)

// tryLockDeviceProvisioning claims the right to provision this device code
// without blocking. A poll that cannot claim it knows another poll's background
// provisioning is still running, and answers "pending" rather than queueing
// behind it — queueing is what turned one slow provision into a 524 for every
// subsequent poll too.
func tryLockDeviceProvisioning(deviceCode string) (func(), bool) {
	deviceProvisioningMu.Lock()
	lock, ok := deviceProvisioningLocks[deviceCode]
	if !ok {
		lock = &sync.Mutex{}
		deviceProvisioningLocks[deviceCode] = lock
	}
	deviceProvisioningMu.Unlock()
	if !lock.TryLock() {
		return nil, false
	}
	return lock.Unlock, true
}

// deviceProvisionOutcome carries a background provision's result back to the
// poll that started it, when it finishes inside the wait window.
type deviceProvisionOutcome struct {
	login DeviceLogin
	err   error
}

// The provisioning result — the Incus certificate add token, remote name, pinned
// project, tenant CIDR — is NOT persisted in device_logins; only status, message
// and provisioned_at are. It used to be handed straight back by the poll that ran
// provisioning, which is why that poll had to be synchronous. Now provisioning
// can outlive the poll that started it, so the result is held here until a later
// poll collects it. A cache miss is safe: provisioning is idempotent, so the
// login simply reports pending and provisioning runs again.
var (
	deviceProvisionResultsMu sync.Mutex
	deviceProvisionResults   = map[string]DeviceLogin{}
)

func storeDeviceProvisionResult(login DeviceLogin) {
	deviceProvisionResultsMu.Lock()
	defer deviceProvisionResultsMu.Unlock()
	deviceProvisionResults[login.DeviceCode] = login
}

func deviceProvisionResult(deviceCode string) (DeviceLogin, bool) {
	deviceProvisionResultsMu.Lock()
	defer deviceProvisionResultsMu.Unlock()
	login, ok := deviceProvisionResults[deviceCode]
	return login, ok
}

func forgetDeviceProvisionResult(deviceCode string) {
	deviceProvisionResultsMu.Lock()
	defer deviceProvisionResultsMu.Unlock()
	delete(deviceProvisionResults, deviceCode)
}

// devicePollProvisionWait bounds how long a poll waits for provisioning before
// answering "pending". It must stay comfortably under a Cloudflare tunnel's
// ~100s origin timeout. A package var so tests can shorten it.
var devicePollProvisionWait = 20 * time.Second

// provisioningInFlight renders a login whose tenant is still being provisioned:
// pending, so the client keeps polling and no CLI token is minted yet.
func provisioningInFlight(login DeviceLogin) DeviceLogin {
	login.Status = DeviceStatusPending
	if strings.TrimSpace(login.Message) == "" {
		login.Message = "Provisioning Personal Tenant."
	}
	return login
}
