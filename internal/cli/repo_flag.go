package cli

import (
	"errors"
	"fmt"

	"github.com/jfrappier/mitch/internal/drift"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
)

// repoFlagUsage is the help text for --repo on "mitch report" and "mitch serve".
const repoFlagUsage = "local git checkout holding your Vault Terraform; Mitch compares the scan with every .tf file in it. Without it, the report has one high finding (MITCH-GIT-001)"

// readRepoFlag reads the Terraform in the --repo checkout. It runs before the
// passphrase is asked for, so a wrong path or a broken .tf file fails fast.
//
// It returns nil, and no error, when --repo was not given. On failure it
// prints why and returns the exit code to use: a usage error when the path
// itself is wrong, a general error when a Terraform file cannot be read.
func readRepoFlag(runContext runContext, command string, path string) (*drift.Repo, int, bool) {
	if path == "" {
		return nil, exitcode.Success, true
	}
	repoLogger := logging.ForComponent(runContext.logger, "repo")

	repo, err := drift.ReadRepo(path)
	if err != nil {
		var pathError *drift.PathError
		if errors.As(err, &pathError) {
			fmt.Fprintf(runContext.stderr, "%s: %v\n", command, err)
			return nil, exitcode.UsageError, false
		}
		repoLogger.Error("reading the Terraform in --repo failed",
			logging.FieldOperation, "read_repo",
			"repo", path,
			logging.FieldError, err.Error(),
			"next_step", "fix the file named in the error; terraform validate shows the same problem",
		)
		return nil, exitcode.GeneralError, false
	}

	repoLogger.Info("read the Terraform in --repo",
		logging.FieldOperation, "read_repo",
		"repo", path,
		"files_read", repo.FilesRead,
		"resources", len(repo.Resources),
		"not_checked", len(repo.NotChecked),
	)
	if repo.FilesRead == 0 {
		repoLogger.Warn("--repo holds no .tf or .tf.json files, so everything in Vault will be reported as not in git",
			logging.FieldOperation, "read_repo",
			"repo", path,
			"next_step", "check that --repo points at the folder that holds your Vault Terraform",
		)
	}
	return &repo, exitcode.Success, true
}
