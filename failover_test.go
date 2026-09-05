package main

import (
	"testing"
	"time"
)

// TestNewFailoverMonitor checks monitor construction and validation.
func TestNewFailoverMonitor(t *testing.T) {
	logger := testLogger(t)

	// Valid construction.
	m := newFailoverMonitor(nil, "tls://203.0.113.10:4440", make([]byte, 32), 500, 10, logger)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}
	if m.directHost != "203.0.113.10:4440" {
		t.Fatalf("directHost = %q", m.directHost)
	}
	if m.maxLatency != 500*time.Millisecond {
		t.Fatalf("maxLatency = %s", m.maxLatency)
	}
	if m.checkEvery != 10*time.Second {
		t.Fatalf("checkEvery = %s", m.checkEvery)
	}

	// Defaults applied.
	m = newFailoverMonitor(nil, "tls://h:1", make([]byte, 32), 0, 0, logger)
	if m.maxLatency != defaultFailoverLatencyMs*time.Millisecond || m.checkEvery != defaultFailoverCheckSec*time.Second {
		t.Fatalf("defaults not applied: %+v", m)
	}

	// Invalid inputs -> nil.
	if newFailoverMonitor(nil, "", make([]byte, 32), 0, 0, logger) != nil {
		t.Fatal("expected nil for empty URI")
	}
	if newFailoverMonitor(nil, "tls://h:1", nil, 0, 0, logger) != nil {
		t.Fatal("expected nil for empty server key")
	}
}

// TestPortOf checks the port extraction helper.
func TestPortOf(t *testing.T) {
	if got := portOf("1.2.3.4:443"); got != "443" {
		t.Fatalf("portOf = %q", got)
	}
	if got := portOf("nonsense"); got != "" {
		t.Fatalf("portOf = %q", got)
	}
}
