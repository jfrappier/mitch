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
//	mitch policy                       prints the base policy (no sudo)
//	mitch policy --sudo                prints the optional sudo add-on policy
//	mitch policy --kv2-mount secret/   prints the KV counting policy for the
//	                                   named mounts (repeat the flag; use
//	                                   --kv1-mount for KV version 1 mounts)
//
// Save the output to a file and load it with:
//
//	vault policy write mitch-scanner mitch-scanner.hcl
func runPolicy(context runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch policy", flag.ContinueOnError)
	flags.SetOutput(context.stderr)

	sudo := flags.Bool("sudo", false, "print the optional sudo add-on policy instead of the base policy")

	// kvMounts collects every --kv1-mount and --kv2-mount, in the order given.
	kvMounts := []checks.KVMount{}
	addKVMount := func(version int) func(string) error {
		return func(value string) error {
			mountPath, err := checks.NormalizeMountPath(value)
			if err != nil {
				return err
			}
			kvMounts = append(kvMounts, checks.KVMount{Path: mountPath, Version: version})
			return nil
		}
	}
	flags.Func("kv1-mount", "print the KV counting policy, including this KV version 1 mount (repeatable)", addKVMount(1))
	flags.Func("kv2-mount", "print the KV counting policy, including this KV version 2 mount (repeatable)", addKVMount(2))

	err := flags.Parse(arguments)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.Success
		}
		return exitcode.UsageError
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(context.stderr, "mitch policy: unexpected argument %q\n", flags.Arg(0))
		return exitcode.UsageError
	}

	// Each call prints exactly one policy, so it can go straight into
	// "vault policy write".
	if *sudo && len(kvMounts) > 0 {
		fmt.Fprintln(context.stderr, "mitch policy: --sudo and --kv1-mount/--kv2-mount print different policies; run them separately")
		return exitcode.UsageError
	}

	switch {
	case *sudo:
		fmt.Fprint(context.stdout, checks.RenderSudoPolicy())
	case len(kvMounts) > 0:
		fmt.Fprint(context.stdout, checks.RenderKVPolicy(kvMounts))
	default:
		fmt.Fprint(context.stdout, checks.RenderBasePolicy())
	}
	return exitcode.Success
}
