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
	"fmt"
	"math/big"
)

// generateKey creates private material for kty (RSA sizes 2048/3072/4096;
// EC curves P-256/P-384/P-521) and returns base64(PKCS#8) + the curve name.
func generateKey(kty string, keySize int, crv string) (string, string, error) {
	var priv any
	var err error
	switch kty {
	case "RSA", "RSA-HSM":
		if keySize == 0 {
			keySize = 2048
		}
		if keySize != 2048 && keySize != 3072 && keySize != 4096 {
			return "", "", fmt.Errorf("unsupported RSA key_size %d", keySize)
		}
		priv, err = rsa.GenerateKey(rand.Reader, keySize)
		crv = ""
	case "EC", "EC-HSM":
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
		return rsa.DecryptPKCS1v15(rand.Reader, k, ciphertext)
	case "RSA-OAEP":
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, k, ciphertext, nil)
	case "RSA-OAEP-256":
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, k, ciphertext, nil)
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}
