package main

import (
	"os"
	"testing"
)

// origUnsetenv removes a variable set by t.Setenv (t.Setenv cannot unset).
func origUnsetenv(key string) {
	_ = os.Unsetenv(key)
}

// withEnv temporarily sets environment variables for the test duration.
func withEnv(t *testing.T, kv map[string]string, unset []string, fn func()) {
	t.Helper()
	for _, k := range unset {
		t.Setenv(k, "")
		origUnsetenv(k)
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
	fn()
}

// TestConfigPathFromOptions verifies all supported plugin_opts forms.
func TestConfigPathFromOptions(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"/etc/shadowsocks/yggss-client.json", "/etc/shadowsocks/yggss-client.json"},
		{"c=/etc/shadowsocks/yggss-client.json", "/etc/shadowsocks/yggss-client.json"},
		{"config=/etc/shadowsocks/yggss-client.json", "/etc/shadowsocks/yggss-client.json"},
		{"s;c=/etc/shadowsocks/yggss-server.json", "/etc/shadowsocks/yggss-server.json"},
		{"s;config=/etc/shadowsocks/yggss-server.json", "/etc/shadowsocks/yggss-server.json"},
		{"c = /path/with spaces/cfg.json", "/path/with spaces/cfg.json"},
		{"s", ""},
		{"key=abc;serverkey=def", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := configPathFromOptions(c.raw); got != c.want {
			t.Errorf("configPathFromOptions(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// TestDetectSIP003 verifies plugin-mode detection from the environment.
// shadowsocks-rust sets SS_LOCAL_*/SS_REMOTE_* but never SS_PLUGIN, so the
// detection must not depend on SS_PLUGIN (regression test).
func TestDetectSIP003(t *testing.T) {
	// No SIP003 env at all -> standalone mode.
	withEnv(t, nil, []string{"SS_LOCAL_HOST", "SS_LOCAL_PORT", "SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_PLUGIN_OPTIONS"}, func() {
		if env := detectSIP003(); env != nil {
			t.Fatal("expected nil env without SIP003 variables")
		}
	})

	// Full environment without SS_PLUGIN (as shadowsocks-rust does) -> plugin mode.
	full := map[string]string{
		"SS_LOCAL_HOST":     "127.0.0.1",
		"SS_LOCAL_PORT":     "4567",
		"SS_REMOTE_HOST":    "203.0.113.10",
		"SS_REMOTE_PORT":    "4440",
		"SS_PLUGIN_OPTIONS": "c=/etc/shadowsocks/yggss-client.json",
	}
	withEnv(t, full, nil, func() {
		env := detectSIP003()
		if env == nil {
			t.Fatal("expected plugin mode without SS_PLUGIN set")
		}
		if env.localAddr() != "127.0.0.1:4567" {
			t.Fatalf("localAddr = %q", env.localAddr())
		}
		if env.remoteAddr() != "203.0.113.10:4440" {
			t.Fatalf("remoteAddr = %q", env.remoteAddr())
		}
		if got := env.options["c"]; got != "/etc/shadowsocks/yggss-client.json" {
			t.Fatalf("option c = %q", got)
		}
	})

	// Incomplete environment -> not a plugin run.
	withEnv(t, map[string]string{"SS_LOCAL_HOST": "127.0.0.1"},
		[]string{"SS_LOCAL_PORT", "SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_PLUGIN_OPTIONS"},
		func() {
			if env := detectSIP003(); env != nil {
				t.Fatal("expected nil env for incomplete SIP003 variables")
			}
		})
}
