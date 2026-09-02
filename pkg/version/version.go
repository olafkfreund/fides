// Package version reports which build of a Fides binary is running. An
// attestation records what was scanned but is useless for tracing which Fides
// produced it without this, and a bug report can't say what the reporter ran.
package version

import "runtime/debug"

// Version is set at build time via
// "-ldflags -X fides/pkg/version.Version=vX.Y.Z" (release.yml, flake.nix,
// Dockerfile.server). Left empty by a plain `go build`, where String falls
// back to the VCS revision the Go toolchain embeds automatically.
var Version string

// String returns the release version if ldflags set one, otherwise the VCS
// revision (short, +dirty if the tree had uncommitted changes) recorded in
// runtime/debug.ReadBuildInfo, otherwise "dev".
//
// -trimpath and -ldflags "-s -w" (both used by the release/Docker builds)
// strip file paths and the symbol table, not the module's VCS settings --
// verified empirically: vcs.revision and vcs.modified survive both. Those
// builds set Version via -X regardless, so this fallback path only matters
// for a developer's plain `go build`.
func String() string {
	if Version != "" {
		return Version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "+dirty"
	}
	return revision
}
