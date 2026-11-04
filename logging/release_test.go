//go:build release

package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestReleaseBuildsWriteNothing(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Writer: &buf, Level: slog.LevelDebug})
	logger.Error("presence registered", "from", "203.0.113.7:443")
	Component(logger, "server").Error("link accepted", "target", "key")
	if buf.Len() != 0 {
		t.Fatalf("a release build wrote a log line: %q", buf.String())
	}
	if Component(nil, "server").Enabled(t.Context(), slog.LevelError) {
		t.Fatal("a component without a logger still logs in a release build")
	}
}
