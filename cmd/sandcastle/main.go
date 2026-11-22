package main

import (
	"os"
	"path/filepath"

	"github.com/moyn-dev/sandcastle-incus/internal/cli"
)

// One fat binary serves every role. Which command tree runs is chosen by how
// the binary is invoked:
//
//   - as `sc-adm` / `sandcastle-admin` (symlinks) → the admin tree (which also
//     hosts the services: `auth-app serve`, `project broker-serve`, …).
//   - as `sc` / `sandcastle` with a leading `admin` arg (`sc admin …`) → the
//     admin tree, minus that arg.
//   - otherwise → the user tree.
//
// The same binary is what admin deploy commands copy into the appliances they
// create, so a container runs its service from this exact executable.
func main() {
	os.Exit(run(commandName(os.Args[0]), os.Args[1:]))
}

func run(name string, args []string) int {
	if isAdminName(name) {
		return cli.ExecuteAdmin(name, args)
	}
	if len(args) > 0 && args[0] == "admin" {
		return cli.ExecuteAdmin(name+" admin", args[1:])
	}
	return cli.Execute(name, args)
}

func isAdminName(name string) bool {
	return name == "sc-adm" || name == "sandcastle-admin"
}

func commandName(argv0 string) string {
	name := filepath.Base(argv0)
	if name == "" || name == "." {
		return "sandcastle"
	}
	return name
}
