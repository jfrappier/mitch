package cli

import (
	"errors"
	"flag"
	"fmt"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/exitcode"
)

// runPolicy prints a Vault policy as HCL.
//
//	mitch policy          prints the base policy (no sudo)
//	mitch policy --sudo   prints the optional sudo add-on policy
//
// Save the output to a file and load it with:
//
//	vault policy write mitch-scanner mitch-scanner.hcl
func runPolicy(context runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch policy", flag.ContinueOnError)
	flags.SetOutput(context.stderr)

	sudo := flags.Bool("sudo", false, "print the optional sudo add-on policy instead of the base policy")

	err := flags.Parse(arguments)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.Success
		}
		return exitcode.UsageError
	}

	if *sudo {
		fmt.Fprint(context.stdout, checks.RenderSudoPolicy())
	} else {
		fmt.Fprint(context.stdout, checks.RenderBasePolicy())
	}
	return exitcode.Success
}
