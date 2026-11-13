// Command mitch is the Mitch command line tool.
//
// All the logic lives in internal/cli. This file only connects it to the
// real command line, standard output, standard error, and exit code.
package main

import (
	"os"

	"github.com/jfrappier/mitch/internal/cli"
)

func main() {
	exitCode := cli.Run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
