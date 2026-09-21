package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// pathCompletionTimeout bounds one completion request: a keystroke waits for
// the Auth App cache (one HTTPS round trip), never for a slow live Incus.
const pathCompletionTimeout = 3 * time.Second

// pathCompletion completes a Sandcastle Path argument: the children of the
// directory the word so far is in, filtered by its last segment, directories
// with a trailing "/" and no space so the user keeps descending. maxDepth is
// the deepest level the command accepts (levelProject for cd, levelMachine
// for machine commands), so nothing offers a machine where a project is
// wanted. A word that is not a path (the colon grammar, or a bare name)
// completes machine names of the current project when the command takes
// machines, and is otherwise left alone.
func pathCompletion(config commandConfig, maxDepth int) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			// Only the first positional is a reference; what follows (a
			// connect command line) gets the shell's own completion.
			return nil, cobra.ShellCompDirectiveDefault
		}
		ctx, cancel := context.WithTimeout(context.Background(), pathCompletionTimeout)
		defer cancel()
		if !isPathReference(toComplete) {
			if maxDepth < levelMachine || strings.Contains(toComplete, ":") {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeCurrentMachines(ctx, config, toComplete), cobra.ShellCompDirectiveNoFileComp
		}
		return completePath(ctx, config, toComplete, maxDepth)
	}
}

// completePath lists the parent of the word and returns the children whose
// name starts with its last segment.
func completePath(ctx context.Context, config commandConfig, toComplete string, maxDepth int) ([]string, cobra.ShellCompDirective) {
	if toComplete == "-" {
		return []string{"-"}, cobra.ShellCompDirectiveNoFileComp
	}
	cut := strings.LastIndex(toComplete, "/")
	if cut < 0 {
		// "~" or ".." alone: complete to a directory the user can descend.
		return []string{toComplete + "/"}, cobra.ShellCompDirectiveNoSpace | cobra.ShellCompDirectiveNoFileComp
	}
	parentText, prefix := toComplete[:cut+1], toComplete[cut+1:]
	parent, err := resolvePath(config, parentText)
	if err != nil || len(parent) >= maxDepth {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if naming.IsPattern(prefix) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	children, err := childrenOf(ctx, config, parent)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := []string{}
	directive := cobra.ShellCompDirectiveNoFileComp
	for _, child := range children {
		if !strings.HasPrefix(child.Name, prefix) {
			continue
		}
		word := parentText + child.Name
		if len(parent)+1 < maxDepth {
			word += "/"
			directive |= cobra.ShellCompDirectiveNoSpace
		}
		completions = append(completions, word)
	}
	return completions, directive
}

// completeCurrentMachines offers the machines of the current project for a
// bare-name word.
func completeCurrentMachines(ctx context.Context, config commandConfig, prefix string) []string {
	position := currentPosition(config)
	if len(position) < levelProject {
		return nil
	}
	children, err := childrenOf(ctx, config, position)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, child := range children {
		if strings.HasPrefix(child.Name, prefix) {
			names = append(names, child.Name)
		}
	}
	return names
}
