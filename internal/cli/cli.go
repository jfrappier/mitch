// Package cli reads the command line and runs the matching Mitch command.
//
// Usage:
//
//	mitch [global flags] <command> [command flags]
//
// Global flags come before the command name:
//
//	--log-format text|json   (default text)
//	--log-level  debug|info|warn|error   (default info)
//
// Command results go to standard output. Log lines go to standard error,
// so results can be piped to a file without log lines mixed in.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/version"
)

// command describes one Mitch subcommand.
type command struct {
	// name is what the user types, for example "scan".
	name string

	// summary is the one-line description shown by "mitch help".
	summary string

	// run does the work. It receives the arguments after the command name
	// and returns an exit code from the exitcode package.
	run func(context runContext, arguments []string) int
}

// runContext carries what every command needs: where to write results and
// the logger to use.
type runContext struct {
	stdout io.Writer
	stderr io.Writer
	logger *slog.Logger
}

// commands returns every command Mitch knows, in the order "mitch help" lists them.
func commands() []command {
	return []command{
		{name: "init", summary: "Create the encrypted database that saves scans", run: runInit},
		{name: "scan", summary: "Scan a Vault cluster and save the inventory (--no-save prints JSON instead)", run: runScan},
		{name: "history", summary: "List saved scans", run: runHistory},
		{name: "passphrase", summary: "Change the passphrase that protects the database", run: runPassphrase},
		{name: "report", summary: "Summarize a saved scan (Markdown in the terminal, --output FILE.json or FILE.md to save)", run: runReport},
		{name: "diff", summary: "Show what changed between two saved scans (--output FILE.json or FILE.md to save)", run: runDiff},
		{name: "export", summary: "Print a saved scan as JSON (SARIF not built yet)", run: runExport},
		{name: "terraform", summary: "Generate Terraform for the scanned Vault config (not built yet)", run: notImplemented("terraform")},
		{name: "policy", summary: "Print the Vault policy Mitch needs (--sudo or --kv2-mount for add-ons)", run: runPolicy},
		{name: "serve", summary: "Start the local read-only web UI (not built yet)", run: notImplemented("serve")},
		{name: "version", summary: "Print the Mitch version", run: runVersion},
		{name: "help", summary: "Show this help", run: runHelp},
	}
}

// Run is the entry point called by main. It returns the process exit code.
//
// arguments is the command line without the program name (os.Args[1:]).
func Run(arguments []string, stdout io.Writer, stderr io.Writer) int {
	// Step 1: read the global flags that come before the command name.
	globalFlags := flag.NewFlagSet("mitch", flag.ContinueOnError)
	globalFlags.SetOutput(stderr)

	logFormat := globalFlags.String("log-format", logging.FormatText, "log output format: text or json")
	logLevel := globalFlags.String("log-level", logging.LevelInfo, "lowest log level to write: debug, info, warn or error")

	err := globalFlags.Parse(arguments)
	if err != nil {
		// The flag package already printed what was wrong.
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.Success
		}
		return exitcode.UsageError
	}

	// Step 2: build the logger. If the flags were bad there is no logger yet,
	// so the error is written as plain text.
	logger, err := logging.New(logging.Options{Output: stderr, Format: *logFormat, Level: *logLevel})
	if err != nil {
		fmt.Fprintf(stderr, "mitch: %v\n", err)
		return exitcode.UsageError
	}
	cliLogger := logging.ForComponent(logger, "cli")

	// Step 3: find the command name. With no command, show help.
	remaining := globalFlags.Args()
	if len(remaining) == 0 {
		printHelp(stdout)
		return exitcode.UsageError
	}

	commandName := remaining[0]
	commandArguments := remaining[1:]

	// Step 4: look up the command and run it.
	selected, found := findCommand(commandName)
	if !found {
		cliLogger.Error("unknown command",
			logging.FieldOperation, "parse_command",
			"command", commandName,
			"next_step", `run "mitch help" to see available commands`,
		)
		return exitcode.UsageError
	}

	context := runContext{stdout: stdout, stderr: stderr, logger: logger}
	exitCode := selected.run(context, commandArguments)
	return exitCode
}

// findCommand looks up a command by name.
func findCommand(name string) (command, bool) {
	for _, candidate := range commands() {
		if candidate.name == name {
			return candidate, true
		}
	}
	return command{}, false
}

// notImplemented returns a run function for a command that is planned but
// not built yet. It fails loudly with its own exit code so nobody mistakes a
// stub for a successful run.
func notImplemented(commandName string) func(runContext, []string) int {
	return func(context runContext, arguments []string) int {
		commandLogger := logging.ForComponent(context.logger, commandName)
		commandLogger.Error("command is not implemented yet",
			logging.FieldOperation, "run_command",
			"command", commandName,
			"next_step", "watch the project README for release notes",
		)
		return exitcode.NotImplemented
	}
}

// runVersion prints the build information.
func runVersion(context runContext, arguments []string) int {
	fmt.Fprintf(context.stdout, "mitch %s (commit %s, built %s)\n",
		version.Version, version.Commit, version.BuildDate)
	return exitcode.Success
}

// runHelp prints the list of commands.
func runHelp(context runContext, arguments []string) int {
	printHelp(context.stdout)
	return exitcode.Success
}

// printHelp writes usage text and every command with its summary.
func printHelp(output io.Writer) {
	fmt.Fprintln(output, "Mitch: a read-only inventory and audit tool for HashiCorp Vault.")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  mitch [--log-format text|json] [--log-level debug|info|warn|error] <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	for _, listed := range commands() {
		fmt.Fprintf(output, "  %-10s %s\n", listed.name, listed.summary)
	}
}
