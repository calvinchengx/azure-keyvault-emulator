package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// jwkParts splits an EC key into its JWK members using PublicKey.Bytes and
// PrivateKey.Bytes rather than the X, Y and D fields, which Go 1.26 deprecates:
// the encoders are fixed-length and big-endian by definition, where .Bytes() on
// a big.Int drops leading zeros and silently produces a short member.
func jwkParts(t *testing.T, k *ecdsa.PrivateKey) (x, y, d string) {
	t.Helper()
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	if len(pub) != 1+2*size {
		t.Fatalf("uncompressed point is %d bytes, want %d", len(pub), 1+2*size)
	}
	scalar, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	u := base64.RawURLEncoding.EncodeToString
	return u(pub[1 : 1+size]), u(pub[1+size:]), u(scalar)
}

// A JWK whose `d` belongs to a DIFFERENT key than its `x` and `y`. Assembling
// the ecdsa.PrivateKey field by field imported this cleanly, because nothing
// checked that the scalar and the point agreed; the key then produced
// signatures that no verifier holding the advertised public key could check.
// Parsing the two halves and comparing them is what makes it an error.
func TestECImportRejectsMismatchedPair(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y, _ := jwkParts(t, a)
	_, _, d := jwkParts(t, b)
	if _, _, _, err := importJWK(jwkImport{Kty: "EC", Crv: "P-256", X: x, Y: y, D: d}); err == nil {
		t.Fatal("a mismatched d/x,y pair imported cleanly")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("rejected, but for the wrong reason: %v", err)
	}
}

// The matching pair must still import, or the check above proves only that EC
// import is broken.
func TestECImportAcceptsMatchingPair(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y, d := jwkParts(t, k)
	_, kty, crv, err := importJWK(jwkImport{Kty: "EC", Crv: "P-256", X: x, Y: y, D: d})
	if err != nil {
		t.Fatalf("a matching pair was rejected: %v", err)
	}
	if kty != "EC" || crv != "P-256" {
		t.Fatalf("kty/crv = %q/%q", kty, crv)
	}
}
