package vault

// BYOK: the Bring-Your-Own-Key transfer blob (the .byok file the Azure BYOK
// tooling produces) imported with real cryptography. The caller creates a KEK
// in this vault, wraps their key with CKM_RSA_AES_KEY_WRAP — an ephemeral
// AES-256 key encrypted to the KEK with RSA-OAEP(SHA-1), the target key
// wrapped under it with AES-KWP (RFC 5649) — and imports the blob; the vault
// unwraps with the KEK's private key. The KEK is software-protected (the
// documented HSM normalisation), but every wrap layer is genuinely verified
// and undone, not skipped.

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// byokBlob is the transfer-blob JSON carried in the JWK's key_hsm member.
type byokBlob struct {
	SchemaVersion string `json:"schema_version"`
	Header        struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Enc string `json:"enc"`
	} `json:"header"`
	Ciphertext string `json:"ciphertext"`
}

// importBYOK unwraps a key_hsm transfer blob using the named KEK's private
// key and returns base64(PKCS#8) of the target key plus its kty and curve.
func (s *Service) importBYOK(vault, keyHSM string) (privateDER, kty, crv string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(keyHSM)
	if err != nil {
		// The BYOK tooling emits standard base64 in places; accept both.
		if raw, err = base64.StdEncoding.DecodeString(keyHSM); err != nil {
			return "", "", "", fmt.Errorf("key_hsm is not valid base64")
		}
	}
	var blob byokBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return "", "", "", fmt.Errorf("key_hsm is not a BYOK transfer blob")
	}
	if !strings.EqualFold(blob.Header.Enc, "CKM_RSA_AES_KEY_WRAP") {
		return "", "", "", fmt.Errorf("unsupported BYOK enc %q (only CKM_RSA_AES_KEY_WRAP)", blob.Header.Enc)
	}
	kekName := kekNameFromKid(blob.Header.Kid)
	if kekName == "" {
		return "", "", "", fmt.Errorf("BYOK header kid %q does not name a key in this vault", blob.Header.Kid)
	}
	kek, err := s.Store.GetKey(vault, kekName)
	if err != nil {
		return "", "", "", fmt.Errorf("KEK %q was not found in this vault", kekName)
	}
	kekPriv, err := parseKey(kek.PrivateDER)
	if err != nil {
		return "", "", "", err
	}
	rsaKEK, ok := kekPriv.(*rsa.PrivateKey)
	if !ok {
		return "", "", "", fmt.Errorf("KEK %q is not an RSA key", kekName)
	}

	ct, err := base64.RawURLEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		if ct, err = base64.StdEncoding.DecodeString(blob.Ciphertext); err != nil {
			return "", "", "", fmt.Errorf("BYOK ciphertext is not valid base64")
		}
	}
	kekLen := rsaKEK.Size()
	if len(ct) <= kekLen {
		return "", "", "", fmt.Errorf("BYOK ciphertext is too short")
	}
	// Layer 1: the ephemeral AES key, RSA-OAEP(SHA-1) to the KEK.
	aesKey, err := rsa.DecryptOAEP(sha1.New(), nil, rsaKEK, ct[:kekLen], nil)
	if err != nil {
		return "", "", "", fmt.Errorf("BYOK unwrap failed: the blob was not wrapped to KEK %q", kekName)
	}
	// Layer 2: the target key, AES-KWP under the ephemeral key.
	targetDER, err := aesKWPUnwrap(aesKey, ct[kekLen:])
	if err != nil {
		return "", "", "", fmt.Errorf("BYOK unwrap failed: %v", err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(targetDER)
	if err != nil {
		if rk, rerr := x509.ParsePKCS1PrivateKey(targetDER); rerr == nil {
			priv = rk
		} else {
			return "", "", "", fmt.Errorf("BYOK payload is not a PKCS#8/PKCS#1 private key")
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return base64.StdEncoding.EncodeToString(der), "RSA", "", nil
	default:
		_ = k
		return "", "", "", fmt.Errorf("BYOK payload must be an RSA key")
	}
}

// kekNameFromKid extracts the key name from a kid URL
// (https://{vault}.vault.azure.net/keys/{name}[/{version}]) or accepts a bare
// name.
func kekNameFromKid(kid string) string {
	if !strings.Contains(kid, "/") {
		return kid
	}
	parts := strings.Split(strings.Trim(kid, "/"), "/")
	for i, p := range parts {
		if p == "keys" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// aesKWPUnwrap implements AES Key Wrap with Padding (RFC 5649) unwrapping,
// built on the RFC 3394 unwrap core. Clean-room from the RFCs.
func aesKWPUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("wrapped key has invalid length %d", len(wrapped))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	var a []byte
	var p []byte
	if len(wrapped) == 16 {
		// Two 64-bit blocks: a single AES-ECB decryption per RFC 5649 §4.1.
		buf := make([]byte, 16)
		block.Decrypt(buf, wrapped)
		a, p = buf[:8], buf[8:]
	} else {
		n := len(wrapped)/8 - 1
		r := make([]byte, len(wrapped)-8)
		copy(r, wrapped[8:])
		aBuf := make([]byte, 8)
		copy(aBuf, wrapped[:8])
		buf := make([]byte, 16)
		for j := 5; j >= 0; j-- {
			for i := n; i >= 1; i-- {
				t := uint64(n*j + i)
				binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(aBuf)^t)
				copy(buf[8:], r[(i-1)*8:i*8])
				block.Decrypt(buf, buf)
				copy(aBuf, buf[:8])
				copy(r[(i-1)*8:i*8], buf[8:])
			}
		}
		a, p = aBuf, r
	}
	// RFC 5649 AIV: A65959A6 || 32-bit MLI.
	if !bytes.Equal(a[:4], []byte{0xA6, 0x59, 0x59, 0xA6}) {
		return nil, fmt.Errorf("integrity check failed")
	}
	mli := int(binary.BigEndian.Uint32(a[4:8]))
	if mli <= 0 || mli > len(p) || len(p)-mli >= 8 {
		return nil, fmt.Errorf("invalid message length")
	}
	for _, b := range p[mli:] {
		if b != 0 {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return p[:mli], nil
}
