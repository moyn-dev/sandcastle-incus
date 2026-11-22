package images

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
)

type SyncRequest struct {
	SourceRef string
}

type SyncPlan struct {
	SourceRef   string `json:"sourceRef"`
	Alias       string `json:"alias"`
	Template    string `json:"template"`
	Description string `json:"description"`
}

type SyncResult struct {
	SyncPlan
	Fingerprint string `json:"fingerprint"`
	Action      string `json:"action"`
}

type Manager interface {
	SyncImage(context.Context, SyncPlan) (SyncResult, error)
}

type BuildRequest struct {
	Template      string
	Tag           string
	Tool          string
	Platform      string
	CodexVersion  string
	ClaudeVersion string
	GeminiVersion string
}

type BuildPlan struct {
	Template      string   `json:"template"`
	Tag           string   `json:"tag"`
	WorkDir       string   `json:"workDir,omitempty"`
	ContextDir    string   `json:"contextDir"`
	Dockerfile    string   `json:"dockerfile"`
	Tool          string   `json:"tool"`
	Platform      string   `json:"platform,omitempty"`
	BuildArgs     []string `json:"buildArgs,omitempty"`
	Command       []string `json:"command"`
	CodexVersion  string   `json:"codexVersion,omitempty"`
	ClaudeVersion string   `json:"claudeVersion,omitempty"`
	GeminiVersion string   `json:"geminiVersion,omitempty"`
}

type BuildResult struct {
	BuildPlan
	Built bool `json:"built"`
}

type Builder interface {
	BuildImage(context.Context, BuildPlan) (BuildResult, error)
}

type ImportRequest struct {
	Template  string
	SourceRef string
	Tool      string
}

type ImportPlan struct {
	Template  string   `json:"template"`
	SourceRef string   `json:"sourceRef"`
	Remote    string   `json:"remote"`
	Alias     string   `json:"alias"`
	Tool      string   `json:"tool"`
	Command   []string `json:"command"`
}

type ImportResult struct {
	ImportPlan
	Imported bool `json:"imported"`
}

type Importer interface {
	ImportImage(context.Context, ImportPlan) (ImportResult, error)
}

type UploadRequest struct {
	Template  string
	SourceRef string
	Alias     string
	Remote    string
	Script    string
}

type UploadPlan struct {
	Template  string   `json:"template"`
	SourceRef string   `json:"sourceRef"`
	Remote    string   `json:"remote"`
	Alias     string   `json:"alias"`
	Script    string   `json:"script"`
	Command   []string `json:"command"`
}

type UploadResult struct {
	UploadPlan
	Uploaded bool `json:"uploaded"`
}

type Uploader interface {
	UploadImage(context.Context, UploadPlan) (UploadResult, error)
}

func PlanSync(admin config.Admin, request SyncRequest) (SyncPlan, error) {
	if err := admin.Validate(); err != nil {
		return SyncPlan{}, err
	}
	source := strings.TrimSpace(request.SourceRef)
	if source == "" {
		return SyncPlan{}, fmt.Errorf("image source reference is required")
	}
	template, alias, err := templateAlias(admin, source)
	if err != nil {
		return SyncPlan{}, err
	}
	return SyncPlan{
		SourceRef:   source,
		Alias:       alias,
		Template:    template,
		Description: "Sandcastle " + template + " image synced from " + source,
	}, nil
}

func PlanBuild(admin config.Admin, request BuildRequest) (BuildPlan, error) {
	if err := admin.Validate(); err != nil {
		return BuildPlan{}, err
	}
	template := strings.ToLower(strings.TrimSpace(request.Template))
	if template == "" {
		return BuildPlan{}, fmt.Errorf("image template is required")
	}
	tool := strings.TrimSpace(request.Tool)
	if tool == "" {
		tool = "docker"
	}
	if err := validateExecutableBase(tool, "image build tool", []string{"docker", "podman"}); err != nil {
		return BuildPlan{}, err
	}
	plan := BuildPlan{
		Template:   template,
		Tool:       tool,
		Platform:   strings.TrimSpace(request.Platform),
		WorkDir:    repoRoot(),
		ContextDir: filepath.Join("images", template),
		Dockerfile: filepath.Join("images", template, "Dockerfile"),
	}
	imageVersion := gitOutput("describe", "--always", "--dirty")
	if imageVersion == "" {
		imageVersion = "unknown"
	}
	imageCommitDate := gitOutput("log", "-1", "--format=%cI")
	if imageCommitDate == "" {
		imageCommitDate = "unknown"
	}
	switch template {
	case "base":
		plan.Tag = firstNonEmpty(request.Tag, admin.Images.Base)
	case "ai":
		plan.Tag = firstNonEmpty(request.Tag, admin.Images.AI)
		plan.CodexVersion = strings.TrimSpace(request.CodexVersion)
		plan.ClaudeVersion = strings.TrimSpace(request.ClaudeVersion)
		plan.GeminiVersion = strings.TrimSpace(request.GeminiVersion)
		if plan.CodexVersion == "" || plan.ClaudeVersion == "" || plan.GeminiVersion == "" {
			return BuildPlan{}, fmt.Errorf("AI image build requires --codex-version, --claude-version, and --gemini-version")
		}
		plan.BuildArgs = append(plan.BuildArgs,
			"SANDCASTLE_BASE_IMAGE="+admin.Images.Base,
		)
		plan.BuildArgs = append(plan.BuildArgs,
			"CODEX_CLI_VERSION="+plan.CodexVersion,
			"CLAUDE_CODE_VERSION="+plan.ClaudeVersion,
			"GEMINI_CLI_VERSION="+plan.GeminiVersion,
		)
	case "dev":
		plan.Tag = firstNonEmpty(request.Tag, admin.Images.Dev)
		plan.CodexVersion = strings.TrimSpace(request.CodexVersion)
		plan.ClaudeVersion = strings.TrimSpace(request.ClaudeVersion)
		if plan.CodexVersion == "" || plan.ClaudeVersion == "" {
			return BuildPlan{}, fmt.Errorf("dev image build requires --codex-version and --claude-version")
		}
		plan.BuildArgs = append(plan.BuildArgs,
			"CODEX_CLI_VERSION="+plan.CodexVersion,
			"CLAUDE_CODE_VERSION="+plan.ClaudeVersion,
		)
	default:
		return BuildPlan{}, fmt.Errorf("unknown image template %q", request.Template)
	}
	if strings.TrimSpace(plan.Tag) == "" {
		return BuildPlan{}, fmt.Errorf("image tag is required")
	}
	plan.BuildArgs = append(plan.BuildArgs,
		"SANDCASTLE_IMAGE_TEMPLATE="+template,
		"SANDCASTLE_IMAGE_TAG="+plan.Tag,
		"SANDCASTLE_IMAGE_VERSION="+imageVersion,
		"SANDCASTLE_IMAGE_COMMIT_DATE="+imageCommitDate,
	)
	plan.Command = buildCommand(plan)
	return plan, nil
}

func PlanImport(admin config.Admin, request ImportRequest) (ImportPlan, error) {
	if err := admin.Validate(); err != nil {
		return ImportPlan{}, err
	}
	template := strings.ToLower(strings.TrimSpace(request.Template))
	if template == "" {
		return ImportPlan{}, fmt.Errorf("image template is required")
	}
	source := strings.TrimSpace(request.SourceRef)
	if source == "" {
		return ImportPlan{}, fmt.Errorf("image source reference is required")
	}
	tool := strings.TrimSpace(request.Tool)
	if tool == "" {
		tool = "incus"
	}
	if err := validateExecutableBase(tool, "image import tool", []string{"incus"}); err != nil {
		return ImportPlan{}, err
	}
	alias, err := aliasForTemplate(admin, template)
	if err != nil {
		return ImportPlan{}, err
	}
	plan := ImportPlan{
		Template:  template,
		SourceRef: source,
		Remote:    strings.TrimSpace(admin.Remote),
		Alias:     alias,
		Tool:      tool,
	}
	plan.Command = importCommand(plan)
	return plan, nil
}

func PlanUpload(admin config.Admin, request UploadRequest) (UploadPlan, error) {
	if err := admin.Validate(); err != nil {
		return UploadPlan{}, err
	}
	template := strings.ToLower(strings.TrimSpace(request.Template))
	if template == "" {
		return UploadPlan{}, fmt.Errorf("image template is required")
	}
	alias := strings.TrimSpace(request.Alias)
	if alias == "" {
		var err error
		alias, err = aliasForTemplate(admin, template)
		if err != nil {
			return UploadPlan{}, err
		}
	}
	source := strings.TrimSpace(request.SourceRef)
	if source == "" {
		source = alias
	}
	remote := strings.TrimSpace(request.Remote)
	if remote == "" {
		remote = strings.TrimSpace(admin.Remote)
	}
	if remote == "" {
		return UploadPlan{}, fmt.Errorf("remote is required")
	}
	script := strings.TrimSpace(request.Script)
	if script == "" {
		script = filepath.Join(repoRoot(), "scripts", "import-docker-image-to-incus.sh")
	}
	plan := UploadPlan{
		Template:  template,
		SourceRef: source,
		Remote:    remote,
		Alias:     alias,
		Script:    script,
	}
	plan.Command = []string{"bash", script, source, alias, remote}
	return plan, nil
}

type LocalBuilder struct {
	Runner CommandRunner
}

type LocalImporter struct {
	Runner CommandRunner
}

type LocalUploader struct {
	Runner CommandRunner
}

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type ExecRunner struct {
	Dir string
}

func (b LocalBuilder) BuildImage(ctx context.Context, plan BuildPlan) (BuildResult, error) {
	var runner CommandRunner = ExecRunner{Dir: plan.WorkDir}
	if b.Runner != nil {
		runner = b.Runner
	}
	if len(plan.Command) == 0 {
		return BuildResult{}, fmt.Errorf("image build command is required")
	}
	if err := runner.Run(ctx, plan.Command[0], plan.Command[1:]...); err != nil {
		return BuildResult{}, err
	}
	return BuildResult{BuildPlan: plan, Built: true}, nil
}

func (i LocalImporter) ImportImage(ctx context.Context, plan ImportPlan) (ImportResult, error) {
	var runner CommandRunner = ExecRunner{}
	if i.Runner != nil {
		runner = i.Runner
	}
	if len(plan.Command) == 0 {
		return ImportResult{}, fmt.Errorf("image import command is required")
	}
	if err := runner.Run(ctx, plan.Command[0], plan.Command[1:]...); err != nil {
		return ImportResult{}, err
	}
	return ImportResult{ImportPlan: plan, Imported: true}, nil
}

func (u LocalUploader) UploadImage(ctx context.Context, plan UploadPlan) (UploadResult, error) {
	var runner CommandRunner = ExecRunner{}
	if u.Runner != nil {
		runner = u.Runner
	}
	if len(plan.Command) == 0 {
		return UploadResult{}, fmt.Errorf("image upload command is required")
	}
	if err := runner.Run(ctx, plan.Command[0], plan.Command[1:]...); err != nil {
		return UploadResult{}, err
	}
	return UploadResult{UploadPlan: plan, Uploaded: true}, nil
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	if r.Dir != "" {
		command.Dir = r.Dir
	}
	if os.Getenv("VERBOSE") == "1" {
		command.Stdout = os.Stderr
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return nil
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func repoRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func gitOutput(args ...string) string {
	command := exec.Command("git", args...)
	command.Dir = repoRoot()
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func buildCommand(plan BuildPlan) []string {
	args := []string{plan.Tool, "build", "-t", plan.Tag, "-f", plan.Dockerfile}
	if plan.Platform != "" {
		args = append(args, "--platform", plan.Platform)
	}
	for _, buildArg := range plan.BuildArgs {
		args = append(args, "--build-arg", buildArg)
	}
	args = append(args, plan.ContextDir)
	return args
}

func validateExecutableBase(value string, label string, allowed []string) error {
	name := filepath.Base(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if name == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s %q is unsupported; expected %s", label, value, strings.Join(allowed, " or "))
}

func importCommand(plan ImportPlan) []string {
	return []string{
		plan.Tool,
		"image",
		"copy",
		plan.SourceRef,
		plan.Remote + ":",
		"--alias",
		plan.Alias,
		"--copy-aliases",
		"--reuse",
	}
}

func aliasForTemplate(admin config.Admin, template string) (string, error) {
	switch template {
	case "base":
		return strings.TrimSpace(admin.Images.Base), nil
	case "ai":
		return strings.TrimSpace(admin.Images.AI), nil
	case "dev":
		return strings.TrimSpace(admin.Images.Dev), nil
	default:
		return "", fmt.Errorf("unknown image template %q", template)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func templateAlias(admin config.Admin, source string) (string, string, error) {
	baseStem := aliasStem(admin.Images.Base)
	aiStem := aliasStem(admin.Images.AI)
	devStem := aliasStem(admin.Images.Dev)
	sourceStem := aliasStem(source)
	switch sourceStem {
	case baseStem:
		return "base", strings.TrimSpace(admin.Images.Base), nil
	case aiStem:
		return "ai", strings.TrimSpace(admin.Images.AI), nil
	case devStem:
		return "dev", strings.TrimSpace(admin.Images.Dev), nil
	default:
		return "", "", fmt.Errorf("image source %q does not match configured Sandcastle base or AI or dev image names", source)
	}
}

func aliasStem(value string) string {
	value = strings.TrimSpace(value)
	if before, _, ok := strings.Cut(value, ":"); ok {
		return before
	}
	return value
}
