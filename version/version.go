// Package version reports the hub-net-node build version.
//
// The rendezvous node advertises the Hub Network protocol major version it
// speaks plus a build identifier. The first release advertises major version 1
// and exactly one role: rendezvous. See PROTOCOL.md and
// protocol-foundations.md for the frozen constants.
package version

import (
	"fmt"

	"github.com/v57/hub-net-node/protocol"
)

// Major is the Hub Network protocol major version implemented by this node.
const Major = protocol.MajorVersion

// Minor is the implemented Hub Network protocol minor version.
const Minor = protocol.MinorVersion

// Build is the node build identifier. Overridden at link time with
// `-ldflags "-X github.com/v57/hub-net-node/version.Build=..."`.
var Build = "dev"

// String returns a "major.minor+build" identifier suitable for health and
// capability responses.
func String() string { return fmt.Sprintf("%d.%d+%s", Major, Minor, Build) }
