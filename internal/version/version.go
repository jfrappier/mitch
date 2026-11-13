// Package version holds the build information printed by "mitch version".
//
// The release build sets these values with the Go linker, for example:
//
//	go build -ldflags "-X github.com/jfrappier/mitch/internal/version.Version=v0.1.0" ./cmd/mitch
//
// A local build without those flags reports "dev".
package version

// Version is the release version, such as "v0.1.0".
var Version = "dev"

// Commit is the git commit the binary was built from.
var Commit = "unknown"

// BuildDate is when the binary was built, in RFC 3339 format.
var BuildDate = "unknown"
