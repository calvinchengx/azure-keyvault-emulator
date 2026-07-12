package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"KV_ADDR", "KV_DATA_DIR", "KV_ENTRA_ISSUER",
		"KV_ENTRA_JWKS_URL", "KV_ENTRA_TLS_INSECURE", "KV_DISABLE_TLS"} {
		t.Setenv(k, "")
	}
}

func TestRunErrors(t *testing.T) {
	clearEnv(t)
	if err := run([]string{"-bogus-flag"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run(nil); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "999.999.999.999:1"}); err == nil {
		t.Fatal("unlistenable addr accepted")
	}
}

// poll waits for the health endpoint to answer.
func poll(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("health never came up at %s", url)
}

func TestRunServesTLS(t *testing.T) {
	clearEnv(t)
	port := freePort(t)
	dir := t.TempDir()
	go func() {
		// Serve blocks until process exit; the goroutine dies with the test.
		_ = run([]string{
			"-entra-issuer", "https://127.0.0.1:1/t/v2.0", // JWKS unreachable is fine: /health needs no token
			"-addr", fmt.Sprintf("127.0.0.1:%d", port),
			"-data-dir", dir,
		})
	}()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	poll(t, client, fmt.Sprintf("https://127.0.0.1:%d/health", port))
	// An authenticated route without a token is a Fabric-shaped 401.
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/secrets?api-version=7.5", port))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /secrets = %d; want 401", resp.StatusCode)
	}
}

func TestRunServesPlainHTTP(t *testing.T) {
	clearEnv(t)
	port := freePort(t)
	go func() {
		_ = run([]string{
			"-entra-issuer", "https://127.0.0.1:1/t/v2.0",
			"-addr", fmt.Sprintf("127.0.0.1:%d", port),
			"-disable-tls",
		})
	}()
	poll(t, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/health", port))
}

func TestRunDataDirAndTLSFailures(t *testing.T) {
	clearEnv(t)
	// -data-dir pointing at an existing FILE: MkdirAll fails.
	dir := t.TempDir()
	file := dir + "/occupied"
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "127.0.0.1:0", "-data-dir", file})
	if err == nil {
		t.Fatal("data-dir-is-a-file accepted")
	}
	// tls subpath blocked: data dir ok, cert persistence fails.
	dir3 := t.TempDir()
	if err := os.WriteFile(dir3+"/tls", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-entra-issuer", "https://x/t/v2.0", "-addr", "127.0.0.1:0", "-data-dir", dir3}); err == nil {
		t.Fatal("broken tls dir accepted")
	}
}

func TestSubcommands(t *testing.T) {
	clearEnv(t)
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	// healthcheck against a live TLS instance succeeds; against a dead port fails.
	port := freePort(t)
	go func() {
		_ = run([]string{"-entra-issuer", "https://127.0.0.1:1/t/v2.0",
			"-addr", fmt.Sprintf("127.0.0.1:%d", port)})
	}()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	poll(t, client, fmt.Sprintf("https://127.0.0.1:%d/health", port))
	t.Setenv("KV_ADDR", fmt.Sprintf("127.0.0.1:%d", port))
	if err := run([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	t.Setenv("KV_ADDR", fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	if err := run([]string{"healthcheck"}); err == nil {
		t.Fatal("healthcheck against dead port succeeded")
	}
	t.Setenv("KV_ADDR", "not-an-addr")
	if err := run([]string{"healthcheck"}); err == nil {
		t.Fatal("healthcheck with bad addr succeeded")
	}
}
