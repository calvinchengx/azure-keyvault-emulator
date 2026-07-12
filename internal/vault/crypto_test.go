package vault

import (
	"testing"
)

// roundTripSign generates a key, signs a digest, and verifies it against the
// derived public JWK — the interop guarantee, unit-level.
func TestCryptoRoundTrips(t *testing.T) {
	cases := []struct {
		kty, crv, sigAlg string
		size             int
	}{
		{"RSA", "", "RS256", 2048},
		{"RSA", "", "RS384", 2048},
		{"RSA", "", "RS512", 2048},
		{"RSA", "", "PS256", 2048},
		{"EC", "P-256", "ES256", 0},
		{"EC", "P-384", "ES384", 0},
		{"EC", "P-521", "ES512", 0},
	}
	for _, c := range cases {
		der, crv, err := generateKey(c.kty, c.size, c.crv)
		if err != nil {
			t.Fatalf("%s/%s generate: %v", c.kty, c.crv, err)
		}
		priv, err := parseKey(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publicJWK(priv, "kid", c.kty, defaultKeyOps); err != nil {
			t.Fatalf("%s jwk: %v", c.sigAlg, err)
		}
		h, _ := hashFor(c.sigAlg)
		digest := make([]byte, h.Size())
		for i := range digest {
			digest[i] = byte(i)
		}
		sig, err := sign(priv, c.sigAlg, digest)
		if err != nil {
			t.Fatalf("%s sign: %v", c.sigAlg, err)
		}
		ok, err := verify(priv, c.sigAlg, digest, sig)
		if err != nil || !ok {
			t.Fatalf("%s verify: ok=%v err=%v", c.sigAlg, ok, err)
		}
		// A flipped bit fails verification.
		sig[0] ^= 0xff
		if ok, _ := verify(priv, c.sigAlg, digest, sig); ok {
			t.Fatalf("%s: tampered signature verified", c.sigAlg)
		}
		_ = crv
	}
}

func TestRSAEncryptRoundTrips(t *testing.T) {
	der, _, err := generateKey("RSA", 2048, "")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := parseKey(der)
	for _, alg := range []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"} {
		ct, err := encrypt(priv, alg, []byte("secret"))
		if err != nil {
			t.Fatalf("%s encrypt: %v", alg, err)
		}
		pt, err := decrypt(priv, alg, ct)
		if err != nil || string(pt) != "secret" {
			t.Fatalf("%s round trip = %q, %v", alg, pt, err)
		}
	}
}

func TestCryptoErrors(t *testing.T) {
	if _, _, err := generateKey("AES", 0, ""); err == nil {
		t.Error("AES key generated")
	}
	if _, _, err := generateKey("RSA", 1024, ""); err == nil {
		t.Error("RSA-1024 generated")
	}
	if _, _, err := generateKey("EC", 0, "P-192"); err == nil {
		t.Error("P-192 generated")
	}
	if _, err := parseKey("!!!"); err == nil {
		t.Error("garbage PKCS#8 parsed")
	}
	if _, ok := hashFor("HS256"); ok {
		t.Error("HS256 accepted")
	}

	rsaDER, _, _ := generateKey("RSA", 2048, "")
	rsaPriv, _ := parseKey(rsaDER)
	ecDER, _, _ := generateKey("EC", 0, "P-256")
	ecPriv, _ := parseKey(ecDER)

	// Cross-type: EC alg on RSA key, RSA alg on EC key.
	if _, err := sign(rsaPriv, "ES256", make([]byte, 32)); err == nil {
		t.Error("ES256 on RSA key")
	}
	if _, err := sign(ecPriv, "RS256", make([]byte, 32)); err == nil {
		t.Error("RS256 on EC key")
	}
	// Wrong digest length.
	if _, err := sign(rsaPriv, "RS256", make([]byte, 10)); err == nil {
		t.Error("wrong digest length accepted")
	}
	// Unsupported algorithm.
	if _, err := sign(rsaPriv, "ZZ999", make([]byte, 32)); err == nil {
		t.Error("bad algorithm accepted")
	}
	// encrypt/decrypt require RSA.
	if _, err := encrypt(ecPriv, "RSA-OAEP", []byte("x")); err == nil {
		t.Error("EC encrypt accepted")
	}
	if _, err := decrypt(ecPriv, "RSA-OAEP", []byte("x")); err == nil {
		t.Error("EC decrypt accepted")
	}
	if _, err := encrypt(rsaPriv, "AES-GCM", []byte("x")); err == nil {
		t.Error("bad encrypt alg accepted")
	}
	if _, err := decrypt(rsaPriv, "AES-GCM", []byte("x")); err == nil {
		t.Error("bad decrypt alg accepted")
	}
	// EC signature of wrong length → not verified (no error).
	if ok, _ := verify(ecPriv, "ES256", make([]byte, 32), []byte("short")); ok {
		t.Error("short EC signature verified")
	}
}
