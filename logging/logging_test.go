package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewDefaultsToJSONInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Writer: &buf})
	logger.Info("hello", slog.String("k", "v"))
	line := buf.String()
	if !strings.Contains(line, `"msg":"hello"`) {
		t.Fatalf("missing msg field: %s", line)
	}
	if !strings.Contains(line, `"level":"INFO"`) {
		t.Fatalf("missing INFO level: %s", line)
	}
	if !strings.Contains(line, `"component"`) {
		// not asserted for the base logger; just ensure JSON valid
		var decoded map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &decoded); err != nil {
			t.Fatalf("not json: %v", err)
		}
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Writer: &buf, Format: FormatText})
	logger.Info("hi")
	if !strings.Contains(buf.String(), "level=INFO") {
		t.Fatalf("text format missing level=INFO: %s", buf.String())
	}
}

func TestComponentTag(t *testing.T) {
	var buf bytes.Buffer
	base := New(Options{Writer: &buf})
	tagged := Component(base, "server")
	tagged.Info("test")
	if !strings.Contains(buf.String(), `"component":"server"`) {
		t.Fatalf("missing component tag: %s", buf.String())
	}
}

func TestComponentNilBaseFallsBackToDefault(t *testing.T) {
	tagged := Component(nil, "anything")
	if tagged == nil {
		t.Fatal("Component returned nil")
	}
}
