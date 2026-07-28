package version

import (
	"strings"
	"testing"

	"github.com/v57/hub-net-node/protocol"
)

func TestMajorMatchesProtocol(t *testing.T) {
	if Major != protocol.MajorVersion {
		t.Fatalf("Major = %d, want protocol.MajorVersion %d", Major, protocol.MajorVersion)
	}
	if Minor != protocol.MinorVersion {
		t.Fatalf("Minor = %d, want protocol.MinorVersion %d", Minor, protocol.MinorVersion)
	}
}

func TestStringFormat(t *testing.T) {
	s := String()
	wantPrefix := "1.0+"
	if !strings.HasPrefix(s, wantPrefix) {
		t.Fatalf("String() = %q, want prefix %q", s, wantPrefix)
	}
	if !strings.HasSuffix(s, Build) {
		t.Fatalf("String() = %q, want suffix Build %q", s, Build)
	}
}
