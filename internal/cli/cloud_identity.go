package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
)

type gcloudRunner func(context.Context, []string, io.Writer) (string, error)

type gcpCloudIdentitySetupRequest struct {
	Tenant         string   `json:"tenant"`
	AuthHostname   string   `json:"auth_hostname,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	GCPProject     string   `json:"gcp_project,omitempty"`
	PoolID         string   `json:"pool_id,omitempty"`
	ProviderID     string   `json:"provider_id"`
	ServiceAccount string   `json:"service_account,omitempty"`
	DisplayName    string   `json:"display_name,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	MachineProject string   `json:"machine_project,omitempty"`
	Machine        string   `json:"machine,omitempty"`
	ConfigName     string   `json:"config_name"`
	SkipAPIEnable  bool     `json:"skip_api_enable,omitempty"`
	Open           bool     `json:"open,omitempty"`
}

type gcpCloudIdentitySetupResult struct {
	ConfigName                     string   `json:"config_name"`
	Tenant                         string   `json:"tenant"`
	GCPProject                     string   `json:"gcp_project"`
	ProjectNumber                  string   `json:"project_number"`
	IssuerURI                      string   `json:"issuer_uri"`
	ProviderResource               string   `json:"provider_resource"`
	CloudIdentityAudience          string   `json:"cloud_identity_audience"`
	ServiceAccountEmail            string   `json:"service_account_email"`
	ServiceAccountImpersonationURL string   `json:"service_account_impersonation_url"`
	ImpersonationMember            string   `json:"impersonation_member"`
	CloudIdentityURL               string   `json:"cloud_identity_url,omitempty"`
	SavedInAuthApp                 bool     `json:"saved_in_auth_app"`
	Roles                          []string `json:"roles,omitempty"`
}

func newCloudIdentityCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:     "cloud-identity",
		Aliases: []string{"cloud"},
		Short:   "Manage tenant cloud identity federation",
	}
	command.AddCommand(newCloudIdentityGCPCommand(config, opts))
	return command
}

func newCloudIdentityGCPCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "gcp",
		Short: "Manage GCP Workload Identity Federation",
	}
	command.AddCommand(newCloudIdentityGCPSetupCommand(config, opts))
	return command
}

func newCloudIdentityGCPSetupCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	request := gcpCloudIdentitySetupRequest{
		Tenant:       strings.TrimSpace(config.adminConfig.Tenant),
		AuthHostname: commandAuthHostname(config, ""),
		ProviderID:   "sandcastle",
		ConfigName:   "gcp",
	}
	command := &cobra.Command{
		Use:   "setup",
		Short: "Configure tenant-scoped GCP Workload Identity Federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			runner := config.gcloudRunner
			if runner == nil {
				runner = runGCloudCLI
			}
			result, err := runGCPCloudIdentitySetup(cmd.Context(), runner, config.stderr, request)
			if err != nil {
				return err
			}
			if strings.TrimSpace(config.adminConfig.AuthToken) != "" {
				client := config.authCloudIdentity
				if client == nil {
					baseURL := commandAuthHostname(config, request.AuthHostname)
					if baseURL != "" {
						client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: config.adminConfig.AuthToken, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
					}
				}
				if client != nil {
					if _, err := client.UpsertCloudIdentity(cmd.Context(), authapp.CloudIdentityUpsertRequest{
						Tenant:                            result.Tenant,
						Name:                              result.ConfigName,
						Provider:                          "gcp",
						GCPAudience:                       result.CloudIdentityAudience,
						GCPServiceAccountImpersonationURL: result.ServiceAccountImpersonationURL,
					}); err != nil {
						return err
					}
					result.SavedInAuthApp = true
				}
			}
			if request.Open {
				if result.CloudIdentityURL == "" {
					return fmt.Errorf("--open requires --auth-hostname")
				}
				open := config.openBrowser
				if open == nil {
					open = openBrowser
				}
				open(result.CloudIdentityURL)
			}
			return writeOutput(config.stdout, opts.output, formatGCPCloudIdentitySetup(result), result)
		},
	}
	command.Flags().StringVar(&request.Tenant, "tenant", request.Tenant, "Sandcastle tenant slug")
	command.Flags().StringVar(&request.AuthHostname, "auth-hostname", request.AuthHostname, "Auth Hostname, for example big.thieso2.dev")
	command.Flags().StringVar(&request.Issuer, "issuer", "", "full issuer URI; overrides --auth-hostname")
	command.Flags().StringVar(&request.GCPProject, "project", "", "GCP project ID; defaults to the active gcloud project")
	command.Flags().StringVar(&request.PoolID, "pool-id", "", "GCP Workload Identity Pool ID; defaults to sandcastle-<tenant>")
	command.Flags().StringVar(&request.ProviderID, "provider-id", request.ProviderID, "GCP Workload Identity Pool provider ID")
	command.Flags().StringVar(&request.ServiceAccount, "service-account", "", "service account name or email; defaults to sandcastle-<tenant>")
	command.Flags().StringVar(&request.DisplayName, "display-name", "", "GCP display name prefix; defaults to Sandcastle <tenant>")
	command.Flags().StringArrayVar(&request.Roles, "role", nil, "project IAM role to grant to the service account; can be repeated")
	command.Flags().StringVar(&request.MachineProject, "machine-project", "", "restrict impersonation to one Sandcastle project; requires --machine")
	command.Flags().StringVar(&request.Machine, "machine", "", "restrict impersonation to one machine; requires --machine-project")
	command.Flags().StringVar(&request.ConfigName, "config-name", request.ConfigName, "suggested Sandcastle Cloud Identity Config name")
	command.Flags().BoolVar(&request.SkipAPIEnable, "skip-api-enable", false, "do not enable required Google APIs")
	command.Flags().BoolVar(&request.Open, "open", false, "open the Auth App Cloud Identity page after setup")
	return command
}

func runGCPCloudIdentitySetup(ctx context.Context, runner gcloudRunner, progress io.Writer, request gcpCloudIdentitySetupRequest) (gcpCloudIdentitySetupResult, error) {
	request.Tenant = strings.TrimSpace(request.Tenant)
	request.AuthHostname = strings.TrimSpace(request.AuthHostname)
	request.Issuer = strings.TrimSpace(request.Issuer)
	request.GCPProject = strings.TrimSpace(request.GCPProject)
	request.PoolID = strings.TrimSpace(request.PoolID)
	request.ProviderID = strings.TrimSpace(request.ProviderID)
	request.ServiceAccount = strings.TrimSpace(request.ServiceAccount)
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	request.MachineProject = strings.TrimSpace(request.MachineProject)
	request.Machine = strings.TrimSpace(request.Machine)
	request.ConfigName = strings.TrimSpace(request.ConfigName)
	if request.Tenant == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--tenant is required")
	}
	if request.ProviderID == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--provider-id is required")
	}
	if request.ConfigName == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--config-name is required")
	}
	if request.MachineProject != "" && request.Machine == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--machine-project requires --machine")
	}
	if request.Machine != "" && request.MachineProject == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--machine requires --machine-project")
	}
	for _, role := range request.Roles {
		if strings.TrimSpace(role) == "" {
			return gcpCloudIdentitySetupResult{}, fmt.Errorf("--role value is required")
		}
	}
	if runner == nil {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("gcloud runner is not configured")
	}

	issuer, err := resolveGCPSetupIssuer(request)
	if err != nil {
		return gcpCloudIdentitySetupResult{}, err
	}
	projectID := request.GCPProject
	if projectID == "" {
		projectID, err = runGCloudQuiet(ctx, runner, "config", "get-value", "project")
		if err != nil {
			return gcpCloudIdentitySetupResult{}, fmt.Errorf("resolve active gcloud project: %w", err)
		}
		projectID = strings.TrimSpace(projectID)
	}
	if projectID == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("--project or active gcloud project is required")
	}

	poolID := request.PoolID
	if poolID == "" {
		poolID = "sandcastle-" + request.Tenant
	}
	serviceAccount := request.ServiceAccount
	if serviceAccount == "" {
		serviceAccount = "sandcastle-" + request.Tenant
	}
	displayName := request.DisplayName
	if displayName == "" {
		displayName = "Sandcastle " + request.Tenant
	}

	projectNumber, err := runGCloudQuiet(ctx, runner, "projects", "describe", projectID, "--format=value(projectNumber)")
	if err != nil {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("resolve GCP project number: %w", err)
	}
	projectNumber = strings.TrimSpace(projectNumber)
	if projectNumber == "" {
		return gcpCloudIdentitySetupResult{}, fmt.Errorf("GCP project number for %q is empty", projectID)
	}

	providerAudience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, poolID, request.ProviderID)
	providerResource := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, poolID, request.ProviderID)

	if !request.SkipAPIEnable {
		if err := runGCloudProgress(ctx, runner, progress, "services", "enable", "iam.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com", "cloudresourcemanager.googleapis.com", "--project="+projectID); err != nil {
			return gcpCloudIdentitySetupResult{}, err
		}
	}

	if gcloudExists(ctx, runner, "iam", "workload-identity-pools", "describe", poolID, "--project="+projectID, "--location=global") {
		fmt.Fprintf(progress, "Workload Identity Pool already exists: %s\n", poolID)
	} else if err := runGCloudProgress(ctx, runner, progress,
		"iam", "workload-identity-pools", "create", poolID,
		"--project="+projectID,
		"--location=global",
		"--display-name="+displayName,
		"--description=Sandcastle workload identities for "+request.Tenant,
	); err != nil {
		return gcpCloudIdentitySetupResult{}, err
	}

	attributeMapping := "google.subject=assertion.sub,attribute.tenant=assertion.tenant,attribute.project=assertion.project,attribute.machine=assertion.machine"
	attributeCondition := "assertion.tenant=='" + request.Tenant + "'"
	providerArgs := []string{
		"iam", "workload-identity-pools", "providers",
		"describe", request.ProviderID,
		"--project=" + projectID,
		"--location=global",
		"--workload-identity-pool=" + poolID,
	}
	if gcloudExists(ctx, runner, providerArgs...) {
		err = runGCloudProgress(ctx, runner, progress,
			"iam", "workload-identity-pools", "providers", "update-oidc", request.ProviderID,
			"--project="+projectID,
			"--location=global",
			"--workload-identity-pool="+poolID,
			"--issuer-uri="+issuer,
			"--allowed-audiences="+providerAudience,
			"--attribute-mapping="+attributeMapping,
			"--attribute-condition="+attributeCondition,
		)
	} else {
		err = runGCloudProgress(ctx, runner, progress,
			"iam", "workload-identity-pools", "providers", "create-oidc", request.ProviderID,
			"--project="+projectID,
			"--location=global",
			"--workload-identity-pool="+poolID,
			"--display-name=Sandcastle",
			"--issuer-uri="+issuer,
			"--allowed-audiences="+providerAudience,
			"--attribute-mapping="+attributeMapping,
			"--attribute-condition="+attributeCondition,
		)
	}
	if err != nil {
		return gcpCloudIdentitySetupResult{}, err
	}

	serviceAccountEmail := serviceAccount
	if strings.Contains(serviceAccount, "@") {
		if !gcloudExists(ctx, runner, "iam", "service-accounts", "describe", serviceAccountEmail, "--project="+projectID) {
			return gcpCloudIdentitySetupResult{}, fmt.Errorf("service account %q does not exist", serviceAccountEmail)
		}
	} else {
		serviceAccountEmail = fmt.Sprintf("%s@%s.iam.gserviceaccount.com", serviceAccount, projectID)
		if gcloudExists(ctx, runner, "iam", "service-accounts", "describe", serviceAccountEmail, "--project="+projectID) {
			fmt.Fprintf(progress, "Service account already exists: %s\n", serviceAccountEmail)
		} else if err := runGCloudProgress(ctx, runner, progress,
			"iam", "service-accounts", "create", serviceAccount,
			"--project="+projectID,
			"--display-name="+displayName,
		); err != nil {
			return gcpCloudIdentitySetupResult{}, err
		}
	}

	member := fmt.Sprintf("principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.tenant/%s", projectNumber, poolID, request.Tenant)
	if request.Machine != "" {
		member = fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/machine:%s/%s/%s", projectNumber, poolID, request.Tenant, request.MachineProject, request.Machine)
	}
	if err := runGCloudProgress(ctx, runner, progress,
		"iam", "service-accounts", "add-iam-policy-binding", serviceAccountEmail,
		"--project="+projectID,
		"--role=roles/iam.workloadIdentityUser",
		"--member="+member,
	); err != nil {
		return gcpCloudIdentitySetupResult{}, err
	}
	for _, role := range request.Roles {
		role = strings.TrimSpace(role)
		if err := runGCloudProgress(ctx, runner, progress,
			"projects", "add-iam-policy-binding", projectID,
			"--member=serviceAccount:"+serviceAccountEmail,
			"--role="+role,
		); err != nil {
			return gcpCloudIdentitySetupResult{}, err
		}
	}

	cloudIdentityURL := ""
	if request.AuthHostname != "" {
		cloudIdentityURL = cloudIdentityWebURL(request.AuthHostname)
	}
	return gcpCloudIdentitySetupResult{
		ConfigName:                     request.ConfigName,
		Tenant:                         request.Tenant,
		GCPProject:                     projectID,
		ProjectNumber:                  projectNumber,
		IssuerURI:                      issuer,
		ProviderResource:               providerResource,
		CloudIdentityAudience:          providerAudience,
		ServiceAccountEmail:            serviceAccountEmail,
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + serviceAccountEmail + ":generateAccessToken",
		ImpersonationMember:            member,
		CloudIdentityURL:               cloudIdentityURL,
		Roles:                          compactStrings(request.Roles),
	}, nil
}

func runGCloudProgress(ctx context.Context, runner gcloudRunner, progress io.Writer, args ...string) error {
	fmt.Fprintf(progress, "+ gcloud %s\n", shellCommandLine(args))
	if _, err := runner(ctx, args, progress); err != nil {
		return fmt.Errorf("gcloud %s: %w", shellCommandLine(args), err)
	}
	return nil
}

func runGCloudQuiet(ctx context.Context, runner gcloudRunner, args ...string) (string, error) {
	out, err := runner(ctx, args, io.Discard)
	if err != nil {
		return "", fmt.Errorf("gcloud %s: %w", shellCommandLine(args), err)
	}
	return strings.TrimSpace(out), nil
}

func gcloudExists(ctx context.Context, runner gcloudRunner, args ...string) bool {
	_, err := runner(ctx, args, io.Discard)
	return err == nil
}

func runGCloudCLI(ctx context.Context, args []string, stderr io.Writer) (string, error) {
	command := exec.CommandContext(ctx, "gcloud", args...)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = stderr
	err := command.Run()
	return strings.TrimSpace(stdout.String()), err
}

func resolveGCPSetupIssuer(request gcpCloudIdentitySetupRequest) (string, error) {
	if request.Issuer != "" {
		return strings.TrimRight(normalizeHTTPSURL(request.Issuer), "/"), nil
	}
	if request.AuthHostname == "" {
		return "", fmt.Errorf("--auth-hostname or --issuer is required")
	}
	return strings.TrimRight(normalizeHTTPSURL(request.AuthHostname), "/") + "/t/" + request.Tenant, nil
}

func normalizeHTTPSURL(value string) string {
	value = strings.TrimSpace(strings.TrimRight(value, "."))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return strings.TrimRight(value, "/")
	}
	return "https://" + strings.TrimRight(value, "/")
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func formatGCPCloudIdentitySetup(result gcpCloudIdentitySetupResult) string {
	var builder strings.Builder
	builder.WriteString("Configured Sandcastle GCP Workload Identity Federation.\n\n")
	builder.WriteString(fmt.Sprintf("GCP project:              %s\n", result.GCPProject))
	builder.WriteString(fmt.Sprintf("Project number:           %s\n", result.ProjectNumber))
	builder.WriteString(fmt.Sprintf("Tenant:                   %s\n", result.Tenant))
	builder.WriteString(fmt.Sprintf("Issuer URI:               %s\n", result.IssuerURI))
	builder.WriteString(fmt.Sprintf("Provider resource:        %s\n", result.ProviderResource))
	builder.WriteString(fmt.Sprintf("Service account:          %s\n", result.ServiceAccountEmail))
	builder.WriteString(fmt.Sprintf("Impersonation member:     %s\n", result.ImpersonationMember))
	builder.WriteString("\nSandcastle Cloud Identity Config:\n")
	builder.WriteString(fmt.Sprintf("Name:                     %s\n", result.ConfigName))
	builder.WriteString("Provider:                 gcp\n")
	builder.WriteString(fmt.Sprintf("Cloud Identity Audience:  %s\n", result.CloudIdentityAudience))
	builder.WriteString(fmt.Sprintf("Impersonation URL:        %s\n", result.ServiceAccountImpersonationURL))
	if result.SavedInAuthApp {
		builder.WriteString("Saved in Auth App:        yes\n")
	} else {
		builder.WriteString("Saved in Auth App:        no (run sc login, then rerun this command)\n")
	}
	if result.CloudIdentityURL != "" {
		builder.WriteString(fmt.Sprintf("Web UI:                   %s\n", result.CloudIdentityURL))
	}
	if len(result.Roles) > 0 {
		builder.WriteString(fmt.Sprintf("Granted service roles:    %s\n", strings.Join(result.Roles, ", ")))
	}
	return strings.TrimRight(builder.String(), "\n")
}

func cloudIdentityWebURL(hostname string) string {
	if hostname == "" {
		return ""
	}
	base, err := url.Parse(normalizeHTTPSURL(hostname))
	if err != nil {
		return ""
	}
	base.Path = "/cloud-identities"
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}
