package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/terraform"
)

// outputDirectoryMode makes generated folders usable only by their owner.
const outputDirectoryMode = 0o700

// runTerraform writes Terraform configuration for the Vault config in a
// saved scan. With no --scan it uses the newest scan.
//
//	mitch terraform --output-dir DIR [--scan ID] [--db PATH] [--passphrase-file FILE]
func runTerraform(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch terraform", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	scanID := flags.String("scan", "", `id of the saved scan (see "mitch history"); default: the newest scan`)
	outputDirectory := flags.String("output-dir", "", "folder to write the Terraform files to; it must not exist yet, or be empty")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	// Check the folder before asking for a passphrase, so a mistake fails fast.
	if *outputDirectory == "" {
		fmt.Fprintln(runContext.stderr, "mitch terraform: --output-dir is required, for example --output-dir vault-terraform")
		return exitcode.UsageError
	}
	err := checkOutputDirectory(*outputDirectory)
	if err != nil {
		fmt.Fprintf(runContext.stderr, "mitch terraform: %v\n", err)
		return exitcode.UsageError
	}

	terraformLogger := logging.ForComponent(runContext.logger, "terraform")
	ctx := context.Background()

	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		terraformLogger.Error("cannot open the database", logging.FieldOperation, "terraform", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	// Step 1: pick and decrypt the scan.
	if *scanID == "" {
		newest, err := newestScanIDs(ctx, opened, 1)
		if err != nil {
			terraformLogger.Error("cannot pick a scan",
				logging.FieldOperation, "terraform",
				logging.FieldError, err.Error(),
				"next_step", `run "mitch scan" to save a scan first`,
			)
			return exitcode.GeneralError
		}
		*scanID = newest[0]
	}
	inventory, exitCode, loaded := loadInventory(ctx, terraformLogger, opened, *scanID)
	if !loaded {
		return exitCode
	}

	// Step 2: build the configuration.
	generated, err := terraform.Generate(*scanID, inventory)
	if err != nil {
		terraformLogger.Error("generating Terraform failed", logging.FieldOperation, "terraform", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	// Step 3: write it.
	err = writeGeneratedFiles(*outputDirectory, generated.Files)
	if err != nil {
		terraformLogger.Error("writing the Terraform files failed",
			logging.FieldOperation, "write_output",
			"output_dir", *outputDirectory,
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}
	terraformLogger.Warn("Terraform files written as plain text; they describe your Vault layout and contain every ACL policy",
		logging.FieldOperation, "write_output",
		"output_dir", *outputDirectory,
	)
	for _, note := range generated.Skipped {
		terraformLogger.Warn("not included in the Terraform", logging.FieldOperation, "terraform", "reason", note)
	}

	counts := generated.Counts
	fmt.Fprintf(runContext.stdout, "Wrote Terraform for scan %s to %s:\n", *scanID, *outputDirectory)
	fmt.Fprintf(runContext.stdout, "  %d namespace(s), %d secrets engine(s), %d auth method(s), %d policy(ies), %d audit device(s)\n",
		counts.Namespaces, counts.SecretsEngines, counts.AuthMethods, counts.Policies, counts.AuditDevices)
	fmt.Fprintln(runContext.stdout, "Next: cd into the folder, run \"terraform init\", then \"terraform plan\". The plan should only import; any change it shows is a difference to review.")
	return exitcode.Success
}

// checkOutputDirectory accepts a folder that does not exist yet, or one that
// is empty. It never writes into a folder that already has files, so an
// existing Terraform project can't be overwritten by mistake.
func checkOutputDirectory(directory string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking --output-dir %s failed: %w", directory, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("--output-dir %s is not empty; pick a new folder so existing files are never overwritten", directory)
	}
	return nil
}

// writeGeneratedFiles writes each file under directory, readable only by its owner.
func writeGeneratedFiles(directory string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fullPath := filepath.Join(directory, filepath.FromSlash(name))
		err := os.MkdirAll(filepath.Dir(fullPath), outputDirectoryMode)
		if err != nil {
			return fmt.Errorf("creating the folder for %s failed: %w", fullPath, err)
		}
		err = writePrivateFile(fullPath, files[name])
		if err != nil {
			return fmt.Errorf("writing %s failed: %w", fullPath, err)
		}
	}
	return nil
}
