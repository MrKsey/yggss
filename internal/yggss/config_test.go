package yggss

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigFile checks JSON config parsing and field mapping.
func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	content := `{
		"server": true,
		"bind": ":4440",
		"destination": "127.0.0.1:8388",
		"key": "aa",
		"client_key": "bb",
		"client_keys": ["cc", "dd"],
		"password": "secret",
		"scheme": "quic",
		"timeout": 42,
		"failover": false,
		"failover_latency_ms": 500,
		"failover_check_sec": 10,
		"peers": ["tls://1.2.3.4:443", "tls://5.6.7.8:443"]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server || cfg.Bind != ":4440" || cfg.Destination != "127.0.0.1:8388" {
		t.Fatalf("unexpected basic fields: %+v", cfg)
	}
	if cfg.Key != "aa" || cfg.ClientKey != "bb" || cfg.Password != "secret" {
		t.Fatalf("unexpected key fields: %+v", cfg)
	}
	if len(cfg.ClientKeys) != 2 || cfg.ClientKeys[0] != "cc" || cfg.ClientKeys[1] != "dd" {
		t.Fatalf("unexpected client_keys: %+v", cfg.ClientKeys)
	}
	if cfg.Scheme != "quic" || cfg.Timeout != 42 {
		t.Fatalf("unexpected scheme/timeout: %+v", cfg)
	}
	if cfg.Failover == nil || *cfg.Failover {
		t.Fatalf("unexpected failover: %+v", cfg.Failover)
	}
	if cfg.FailoverLatency != 500 || cfg.FailoverCheck != 10 {
		t.Fatalf("unexpected failover params: %+v", cfg)
	}
	if len(cfg.Peers) != 2 || cfg.Peers[0] != "tls://1.2.3.4:443" {
		t.Fatalf("unexpected peers: %+v", cfg.Peers)
	}
}

// TestLoadConfigFileInvalid ensures broken JSON produces an error.
func TestLoadConfigFileInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

// TestExampleConfigs validates all bundled example plugin configs parse cleanly.
func TestExampleConfigs(t *testing.T) {
	matches, err := filepath.Glob("../../examples/*/yggss*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no example configs found")
	}
	for _, m := range matches {
		if _, err := loadConfigFile(m); err != nil {
			t.Errorf("example config %s failed to parse: %v", m, err)
		}
	}
}

// TestFindConfigPath checks the -c pre-scan in both supported forms.
func TestFindConfigPath(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-c", "a.json"}, "a.json"},
		{[]string{"-c=b.json"}, "b.json"},
		{[]string{"-s", "-c", "c.json", "-v"}, "c.json"},
		{[]string{"-s"}, ""},
	}
	for _, c := range cases {
		if got := findConfigPath(c.args); got != c.want {
			t.Errorf("findConfigPath(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}
