package vault

// Real cryptography for the /keys surface: RSA and EC generation, JWK
// derivation, and the sign/verify/encrypt/decrypt/wrap/unwrap algorithms.
// Signatures verify against the JWK the API returns — interop, not stubs.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// generateKey creates private material for kty (RSA sizes 2048/3072/4096;
// EC curves P-256/P-384/P-521) and returns base64(PKCS#8) + the curve name.
func generateKey(kty string, keySize int, crv string) (string, string, error) {
	var priv any
	var err error
	switch kty {
	case "RSA":
		// Sizes are passed as literals rather than a checked variable so the
		// 2048-bit floor is visible to callers and to static analysis.
		switch keySize {
		case 0, 2048:
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
		case 3072:
			priv, err = rsa.GenerateKey(rand.Reader, 3072)
		case 4096:
			priv, err = rsa.GenerateKey(rand.Reader, 4096)
		default:
			return "", "", fmt.Errorf("unsupported RSA key_size %d", keySize)
		}
		crv = ""
	case "EC":
		var curve elliptic.Curve
		switch crv {
		case "", "P-256":
			curve, crv = elliptic.P256(), "P-256"
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return "", "", fmt.Errorf("unsupported curve %q", crv)
		}
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "oct", "oct-HSM":
		// Real Key Vault (vaults, as opposed to Managed HSM) supports RSA
		// and EC only; symmetric keys live in Managed HSM. Refuse as the
		// real service does.
		return "", "", fmt.Errorf("key type %s is not supported in this vault; symmetric keys require Managed HSM", kty)
	default:
		return "", "", fmt.Errorf("unsupported kty %q", kty)
	}
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(der), crv, nil
}

// parseKey loads the stored PKCS#8 material.
func parseKey(privateDER string) (any, error) {
	der, err := base64.StdEncoding.DecodeString(privateDER)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64uDecode tolerantly decodes base64url, with or without padding — JWK
// members are unpadded, but some clients pad them.
func b64uDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// jwkImport is the private JWK the import-key call carries (RFC 7517 members).
type jwkImport struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	D      string   `json:"d"`
	P      string   `json:"p"`
	Q      string   `json:"q"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	KeyOps []string `json:"key_ops"`
	// KeyHSM carries the BYOK transfer blob (the REST JWK's key_hsm member).
	KeyHSM string `json:"key_hsm"`
}

// samePublicKey reports whether two public keys are equal, using the standard
// library's per-type Equal method.
func samePublicKey(a, b any) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ae, ok := a.(equaler)
	return ok && ae.Equal(b)
}

// ktyOf reports "RSA" or "EC" for a parsed private key (empty for neither).
func ktyOf(priv any) string {
	switch priv.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "EC"
	}
	return ""
}

// importJWK reconstructs a private key from a JWK and returns base64(PKCS#8)
// plus the normalized kty and curve. RSA needs n/e/d/p/q; EC needs crv/x/y/d.
func importJWK(j jwkImport) (privateDER, kty, crv string, err error) {
	switch normalizeKty(j.Kty) {
	case "oct", "oct-HSM":
		// As in real Key Vault: vaults hold RSA/EC keys only; symmetric
		// keys require Managed HSM.
		return "", "", "", fmt.Errorf("key type %s is not supported in this vault; symmetric keys require Managed HSM", j.Kty)
	case "RSA":
		mods := map[string]string{"n": j.N, "e": j.E, "d": j.D, "p": j.P, "q": j.Q}
		vals := map[string]*big.Int{}
		for name, s := range mods {
			if s == "" {
				return "", "", "", fmt.Errorf("RSA import requires the %q member", name)
			}
			b, derr := b64uDecode(s)
			if derr != nil {
				return "", "", "", fmt.Errorf("member %q is not valid base64url", name)
			}
			vals[name] = new(big.Int).SetBytes(b)
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: vals["n"], E: int(vals["e"].Int64())},
			D:         vals["d"],
			Primes:    []*big.Int{vals["p"], vals["q"]},
		}
		priv.Precompute()
		if verr := priv.Validate(); verr != nil {
			return "", "", "", fmt.Errorf("invalid RSA key material: %w", verr)
		}
		der, merr := x509.MarshalPKCS8PrivateKey(priv)
		if merr != nil {
			return "", "", "", merr
		}
		return base64.StdEncoding.EncodeToString(der), "RSA", "", nil
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return "", "", "", fmt.Errorf("unsupported curve %q", j.Crv)
		}
		mods := map[string]string{"x": j.X, "y": j.Y, "d": j.D}
		vals := map[string]*big.Int{}
		for name, s := range mods {
			if s == "" {
				return "", "", "", fmt.Errorf("EC import requires the %q member", name)
			}
			b, derr := b64uDecode(s)
			if derr != nil {
				return "", "", "", fmt.Errorf("member %q is not valid base64url", name)
			}
			vals[name] = new(big.Int).SetBytes(b)
		}
		// Parsed rather than assembled by field. Setting D, X and Y directly is
		// deprecated as of Go 1.26 (raw coordinates can produce invalid keys and
		// defeat internal optimizations), and the parsers validate what the old
		// code had to check by hand, or did not check at all: the point is on
		// the curve, the scalar is in range, and d actually corresponds to the
		// x and y that came with it. A JWK carrying a mismatched pair used to
		// import as a working key that produced signatures nobody could verify.
		size := (curve.Params().BitSize + 7) / 8
		for _, name := range []string{"x", "y", "d"} {
			if len(vals[name].Bytes()) > size {
				return "", "", "", fmt.Errorf("member %q is too long for curve %s", name, j.Crv)
			}
		}
		point := make([]byte, 1+2*size)
		point[0] = 4 // uncompressed
		vals["x"].FillBytes(point[1 : 1+size])
		vals["y"].FillBytes(point[1+size:])
		pub, perr := ecdsa.ParseUncompressedPublicKey(curve, point)
		if perr != nil {
			return "", "", "", fmt.Errorf("EC public point is not on curve %s", j.Crv)
		}
		scalar := make([]byte, size)
		vals["d"].FillBytes(scalar)
		priv, kerr := ecdsa.ParseRawPrivateKey(curve, scalar)
		if kerr != nil {
			return "", "", "", fmt.Errorf("EC private scalar is not valid for curve %s", j.Crv)
		}
		if !priv.PublicKey.Equal(pub) {
			return "", "", "", fmt.Errorf("EC private key does not match the supplied public point")
		}
		der, merr := x509.MarshalPKCS8PrivateKey(priv)
		if merr != nil {
			return "", "", "", merr
		}
		return base64.StdEncoding.EncodeToString(der), "EC", j.Crv, nil
	}
	return "", "", "", fmt.Errorf("unsupported kty %q", j.Kty)
}

// buildReleaseToken produces a signed JWS whose payload is claims — the
// "signed object containing the released key" a Secure Key Release returns. A
// fresh RSA key signs it and its public JWK rides in the header, so the token
// is self-verifiable (real crypto, not a stub string). The SDK returns the
// value verbatim; the signature makes it a well-formed release token.
func buildReleaseToken(claims map[string]any) (string, error) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	pubJWK := map[string]any{
		"kty": "RSA",
		"n":   b64u(signer.N.Bytes()),
		"e":   b64u(big.NewInt(int64(signer.E)).Bytes()),
	}
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "jwk": pubJWK})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64u(header) + "." + b64u(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64u(sig), nil
}

// randomBytes returns count cryptographically-random bytes (1..128, the
// service limit).
func randomBytes(count int) ([]byte, error) {
	if count < 1 || count > 128 {
		return nil, fmt.Errorf("count must be between 1 and 128")
	}
	b := make([]byte, count)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// publicJWK renders the public portion (n/e or crv/x/y) — never the private.
func publicJWK(priv any, kid, kty string, keyOps []string) (map[string]any, error) {
	jwk := map[string]any{"kid": kid, "kty": kty, "key_ops": keyOps}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		jwk["n"] = b64u(k.N.Bytes())
		jwk["e"] = b64u(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		jwk["crv"] = curveName(k.Curve)
		jwk["x"] = b64u(k.X.FillBytes(make([]byte, size)))
		jwk["y"] = b64u(k.Y.FillBytes(make([]byte, size)))
	default:
		return nil, fmt.Errorf("unsupported key type %T", priv)
	}
	return jwk, nil
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "P-256"
	}
}

// hashFor maps a signature algorithm to its digest spec.
func hashFor(alg string) (crypto.Hash, bool) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, true
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, true
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, true
	}
	return 0, false
}

// sign signs a caller-provided digest (Key Vault semantics: the client
// hashes). EC signatures use the raw r||s encoding Azure emits.
func sign(priv any, alg string, digest []byte) ([]byte, error) {
	h, ok := hashFor(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("digest length %d does not match %s", len(digest), alg)
	}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		switch alg[0] {
		case 'R':
			return rsa.SignPKCS1v15(rand.Reader, k, h, digest)
		case 'P':
			return rsa.SignPSS(rand.Reader, k, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return nil, fmt.Errorf("algorithm %q requires an EC key", alg)
	case *ecdsa.PrivateKey:
		if alg[0] != 'E' {
			return nil, fmt.Errorf("algorithm %q requires an RSA key", alg)
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", priv)
}

// verify checks a signature produced by sign (or any conforming signer).
func verify(priv any, alg string, digest, sig []byte) (bool, error) {
	h, ok := hashFor(alg)
	if !ok {
		return false, fmt.Errorf("unsupported algorithm %q", alg)
	}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		switch alg[0] {
		case 'R':
			return rsa.VerifyPKCS1v15(&k.PublicKey, h, digest, sig) == nil, nil
		case 'P':
			return rsa.VerifyPSS(&k.PublicKey, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil, nil
		}
		return false, fmt.Errorf("algorithm %q requires an EC key", alg)
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false, nil
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(&k.PublicKey, digest, r, s), nil
	}
	return false, fmt.Errorf("unsupported key type %T", priv)
}

// encrypt implements RSA1_5 / RSA-OAEP / RSA-OAEP-256 (wrap uses the same).
func encrypt(priv any, alg string, plaintext []byte) ([]byte, error) {
	k, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("encryption requires an RSA key")
	}
	switch alg {
	case "RSA1_5":
		// Go 1.26 deprecates PKCS #1 v1.5 encryption because it is dangerous,
		// and it is right. It stays because **Azure Key Vault offers RSA1_5**:
		// it is a documented algorithm of the service this emulates, real
		// clients select it, and an emulator that refused it would report a
		// parity gap that the service does not have. The deprecation is advice
		// to people designing new protocols; this code is implementing
		// somebody else's existing one.
		//nolint:staticcheck // SA1019: RSA1_5 is part of the emulated API surface
		return rsa.EncryptPKCS1v15(rand.Reader, &k.PublicKey, plaintext)
	case "RSA-OAEP":
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, &k.PublicKey, plaintext, nil)
	case "RSA-OAEP-256":
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.PublicKey, plaintext, nil)
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// decrypt inverts encrypt.
func decrypt(priv any, alg string, ciphertext []byte) ([]byte, error) {
	k, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decryption requires an RSA key")
	}
	switch alg {
	case "RSA1_5":
		// As above. The specific hazard the deprecation names, that whether
		// this returns an error leaks secret information to an attacker who
		// can run it repeatedly, is a property of the algorithm that the real
		// service shares. Diverging here would hide it rather than fix it, and
		// hiding a real service's weakness is the opposite of emulating it.
		//nolint:staticcheck // SA1019: RSA1_5 is part of the emulated API surface
		return rsa.DecryptPKCS1v15(rand.Reader, k, ciphertext)
	case "RSA-OAEP":
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, k, ciphertext, nil)
	case "RSA-OAEP-256":
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, k, ciphertext, nil)
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}
