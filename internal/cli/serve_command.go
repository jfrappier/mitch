package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/web"
)

// defaultListenAddress keeps the UI on this machine only.
const defaultListenAddress = "127.0.0.1:8484"

// shutdownTimeout is how long open page loads get to finish after Ctrl+C.
const shutdownTimeout = 5 * time.Second

// stopSignalContext returns a context that ends on Ctrl+C (SIGINT) or
// SIGTERM, which is what "docker stop" sends. Tests replace it.
var stopSignalContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// runServe starts the read-only web UI over the saved scans.
//
//	mitch serve [--listen ADDRESS:PORT] [--db PATH] [--passphrase-file FILE]
func runServe(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch serve", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	listenAddress := flags.String("listen", defaultListenAddress, "address and port to listen on; anything other than 127.0.0.1 or ::1 can be reached from other machines")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	// Check the address before asking for a passphrase, so a typo fails fast.
	host, _, err := net.SplitHostPort(*listenAddress)
	if err != nil {
		fmt.Fprintf(runContext.stderr, "mitch serve: --listen %q is not ADDRESS:PORT: %v\n", *listenAddress, err)
		return exitcode.UsageError
	}

	serveLogger := logging.ForComponent(runContext.logger, "serve")
	ctx, stop := stopSignalContext()
	defer stop()

	// Step 1: unlock the database. It stays open while the UI runs.
	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		serveLogger.Error("cannot open the database", logging.FieldOperation, "serve", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	// Step 2: make a new access token for this run only.
	accessToken, err := web.NewAccessToken()
	if err != nil {
		serveLogger.Error("cannot make an access token", logging.FieldOperation, "serve", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	server, err := web.NewServer(opened, runContext.logger, accessToken)
	if err != nil {
		serveLogger.Error("cannot set up the web UI", logging.FieldOperation, "serve", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	// Step 3: open the port now, so "address already in use" fails here,
	// and so port 0 (any free port) shows the real port in the link.
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		serveLogger.Error("cannot listen", logging.FieldOperation, "serve", "listen", *listenAddress, logging.FieldError, err.Error(),
			"next_step", "pick another port with --listen, for example --listen 127.0.0.1:8485")
		return exitcode.GeneralError
	}

	if !isLoopbackHost(host) {
		serveLogger.Warn("the web UI can be reached from other machines, over plain HTTP",
			logging.FieldOperation, "serve",
			"listen", *listenAddress,
			"next_step", "only do this inside a container whose port is published to 127.0.0.1, or behind a TLS proxy",
		)
	}

	// Step 4: print the link. The token is in it, so it goes to the
	// terminal only, never to the log.
	fmt.Fprintf(runContext.stdout, "Mitch web UI is running. Open this link (it holds this run's access token):\n\n  %s\n\nPress Ctrl+C to stop.\n",
		loginLink(listener.Addr(), accessToken))

	// Step 5: serve until Ctrl+C or SIGTERM.
	httpServer := web.NewHTTPServer(*listenAddress, server.Handler())
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- httpServer.Serve(listener)
	}()

	select {
	case err = <-serveErrors:
		serveLogger.Error("the web UI stopped", logging.FieldOperation, "serve", logging.FieldError, err.Error())
		return exitcode.GeneralError
	case <-ctx.Done():
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = httpServer.Shutdown(shutdownContext)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		serveLogger.Error("stopping the web UI failed", logging.FieldOperation, "serve", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	serveLogger.Info("web UI stopped", logging.FieldOperation, "serve")
	return exitcode.Success
}

// isLoopbackHost reports whether host only accepts connections from this
// machine ("localhost", 127.0.0.0/8 or ::1).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// loginLink is the address to open in a browser. When listening on every
// address (0.0.0.0 or ::), the link uses 127.0.0.1, which works on the
// machine itself and through a port published by Docker.
func loginLink(listenAddress net.Addr, accessToken string) string {
	host, port, err := net.SplitHostPort(listenAddress.String())
	if err != nil {
		host = "127.0.0.1"
		port = "8484"
	}
	address := net.ParseIP(host)
	if address == nil || address.IsUnspecified() {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/login?token=%s", net.JoinHostPort(host, port), accessToken)
}
