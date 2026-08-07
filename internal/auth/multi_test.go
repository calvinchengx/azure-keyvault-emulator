package auth

// Multi-issuer validation: tokens from any trusted issuer validate against
// that issuer's own JWKS, and the verifying key is bound to the iss claim.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func jwksServer(t *testing.T, kid string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func TestMultiIssuer(t *testing.T) {
	srvA, keyA := jwksServer(t, "kid-a")
	srvB, keyB := jwksServer(t, "kid-b")
	now := int64(1_700_000_000)
	v := NewMulti([][2]string{
		{"https://issuer-a/t/v2.0", srvA.URL},
		{"https://issuer-b/t/v2.0", srvB.URL},
	}, false, func() int64 { return now }, srvA.Client())

	// A token from each issuer validates.
	for _, c := range []struct {
		iss string
		key *rsa.PrivateKey
		kid string
	}{
		{"https://issuer-a/t/v2.0", keyA, "kid-a"},
		{"https://issuer-b/t/v2.0", keyB, "kid-b"},
	} {
		tok := mint(t, c.key, mintOpts{iss: c.iss, aud: "https://vault.azure.net",
			exp: now + 600, oid: "user-1", kid: c.kid})
		if _, err := v.Validate(tok); err != nil {
			t.Fatalf("token from %s rejected: %v", c.iss, err)
		}
	}

	// Cross-wiring is refused: issuer A's iss claim signed by B's key. The
	// signature verifies under B's key, but the key is bound to issuer B.
	tok := mint(t, keyB, mintOpts{iss: "https://issuer-a/t/v2.0",
		aud: "https://vault.azure.net", exp: now + 600, oid: "user-1", kid: "kid-b"})
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("issuer-a claim signed by issuer-b's key was accepted")
	}
	// An unknown issuer's token is refused even with a known key id shape.
	tok = mint(t, keyA, mintOpts{iss: "https://issuer-c/t/v2.0",
		aud: "https://vault.azure.net", exp: now + 600, oid: "user-1", kid: "kid-a"})
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("unknown issuer accepted")
	}
}
