package config

import "testing"

func TestFinishDerivations(t *testing.T) {
	c := &Config{EntraIssuer: "https://e:1/tid/v2.0", SoftDeleteRetentionDays: 90}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if c.EntraJWKSURL != "https://e:1/tid/discovery/v2.0/keys" {
		t.Fatalf("jwks = %q", c.EntraJWKSURL)
	}
	if c.EntraAuthority != "https://e:1/tid" {
		t.Fatalf("authority = %q", c.EntraAuthority)
	}
}

func TestFinishValidation(t *testing.T) {
	if err := (&Config{SoftDeleteRetentionDays: 90}).Finish(); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if err := (&Config{EntraIssuer: "not-a-url", SoftDeleteRetentionDays: 90}).Finish(); err == nil {
		t.Fatal("non-URL issuer accepted")
	}
	for _, days := range []int{0, 6, 91} {
		c := &Config{EntraIssuer: "https://e/t/v2.0", SoftDeleteRetentionDays: days}
		if err := c.Finish(); err == nil {
			t.Fatalf("retention %d accepted", days)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("KV_ENTRA_ISSUER", "https://e/t/v2.0")
	t.Setenv("KV_ADDR", ":9999")
	t.Setenv("KV_ENTRA_TLS_INSECURE", "true")
	t.Setenv("KV_SOFT_DELETE_RETENTION_DAYS", "7")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":9999" || !c.EntraTLSInsecure || c.SoftDeleteRetentionDays != 7 || c.DefaultVault != "emulator" {
		t.Fatalf("FromEnv = %+v", c)
	}
	t.Setenv("KV_ENTRA_ISSUER", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv without issuer succeeded")
	}
}

func TestBoolEnvShapes(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "TRUE": true, "yes": true, "on": true, "0": false, "": false} {
		t.Setenv("KV_TEST_BOOL", v)
		if got := boolEnv("KV_TEST_BOOL"); got != want {
			t.Errorf("boolEnv(%q) = %v", v, got)
		}
	}
}
