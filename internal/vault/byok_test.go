package vault

// BYOK round trip: the test plays the customer's HSM tooling — it wraps a
// real RSA key with CKM_RSA_AES_KEY_WRAP (test-side RFC 3394/5649 wrap
// implementation) to the vault's KEK, imports the blob, and then proves the
// vault holds the same key by verifying a vault-produced signature against
// the ORIGINAL public key.

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func mustEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// kwpWrap is the RFC 5649 wrap (test-side counterpart of aesKWPUnwrap).
func kwpWrap(t *testing.T, kek, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	mli := len(plain)
	padded := append(append([]byte{}, plain...), make([]byte, (8-mli%8)%8)...)
	aiv := []byte{0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(aiv[4:], uint32(mli))
	if len(padded) == 8 {
		buf := make([]byte, 16)
		copy(buf, aiv)
		copy(buf[8:], padded)
		block.Encrypt(buf, buf)
		return buf
	}
	n := len(padded) / 8
	a := append([]byte{}, aiv...)
	r := append([]byte{}, padded...)
	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf, a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			tv := uint64(n*j + i)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^tv)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(a, r...)
}

func makeBYOKBlob(t *testing.T, kekPub *rsa.PublicKey, kid string, targetDER []byte) string {
	t.Helper()
	ephemeral := make([]byte, 32)
	if _, err := rand.Read(ephemeral); err != nil {
		t.Fatal(err)
	}
	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, kekPub, ephemeral, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct := append(wrappedKey, kwpWrap(t, ephemeral, targetDER)...)
	blob, _ := json.Marshal(map[string]any{
		"schema_version": "1.0.0",
		"header":         map[string]string{"kid": kid, "alg": "dir", "enc": "CKM_RSA_AES_KEY_WRAP"},
		"ciphertext":     base64.RawURLEncoding.EncodeToString(ct),
	})
	return base64.RawURLEncoding.EncodeToString(blob)
}

func TestBYOKImportRoundTrip(t *testing.T) {
	s, st := newService(t, "")

	// The vault-held KEK the customer wraps to.
	do(s.createKey, "POST", "/x", `{"kty":"RSA","key_size":2048}`, map[string]string{"name": "kek"})
	kekVersion, err := st.GetKey("emulator", "kek")
	if err != nil {
		t.Fatal(err)
	}
	kekPriv, err := parseKey(kekVersion.PrivateDER)
	if err != nil {
		t.Fatal(err)
	}
	kekPub := &kekPriv.(*rsa.PrivateKey).PublicKey

	// The customer's key, wrapped exactly as the BYOK tooling does.
	target, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	targetDER, err := x509.MarshalPKCS8PrivateKey(target)
	if err != nil {
		t.Fatal(err)
	}
	keyHSM := makeBYOKBlob(t, kekPub, "https://emulator.vault.azure.net/keys/kek", targetDER)

	body := fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, keyHSM)
	nv := map[string]string{"name": "migrated"}
	w := do(s.importKey, "PUT", "/x", body, nv)
	if w.Code != http.StatusOK {
		t.Fatalf("BYOK import = %d %s", w.Code, w.Body.Bytes())
	}

	// The vault now signs with the customer's key: verify against the
	// ORIGINAL public key, outside the emulator entirely.
	digest := sha256.Sum256([]byte("byok proves possession"))
	sw := do(s.cryptoOp("sign"), "POST", "/x",
		fmt.Sprintf(`{"alg":"RS256","value":%q}`, base64.RawURLEncoding.EncodeToString(digest[:])), nv)
	if sw.Code != http.StatusOK {
		t.Fatalf("sign with imported key = %d %s", sw.Code, sw.Body.Bytes())
	}
	var sig struct{ Value string }
	_ = json.Unmarshal(sw.Body.Bytes(), &sig)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sig.Value)
	if err := rsa.VerifyPKCS1v15(&target.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		t.Fatalf("imported key is not the wrapped key: %v", err)
	}

	// Negatives: unknown KEK, tampered ciphertext, garbage blob.
	bad := makeBYOKBlob(t, kekPub, "https://emulator.vault.azure.net/keys/nokek", targetDER)
	if w := do(s.importKey, "PUT", "/x", fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, bad),
		map[string]string{"name": "m2"}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("unknown KEK = %d %s", w.Code, w.Body.Bytes())
	}
	raw, _ := base64.RawURLEncoding.DecodeString(keyHSM)
	var blob map[string]any
	_ = json.Unmarshal(raw, &blob)
	ct, _ := base64.RawURLEncoding.DecodeString(blob["ciphertext"].(string))
	ct[len(ct)-1] ^= 0xff
	blob["ciphertext"] = base64.RawURLEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(blob)
	if w := do(s.importKey, "PUT", "/x",
		fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, base64.RawURLEncoding.EncodeToString(tampered)),
		map[string]string{"name": "m3"}); w.Code != http.StatusBadRequest {
		t.Fatalf("tampered blob = %d %s", w.Code, w.Body.Bytes())
	}
	if w := do(s.importKey, "PUT", "/x", `{"key":{"kty":"RSA-HSM","key_hsm":"bm90LWEtYmxvYg"}}`,
		map[string]string{"name": "m4"}); w.Code != http.StatusBadRequest {
		t.Fatalf("garbage blob = %d %s", w.Code, w.Body.Bytes())
	}
	// More refusals: bare/std-base64 forms, non-RSA KEK, EC target, short
	// ciphertext, kid without a key segment.
	if name := kekNameFromKid("kek"); name != "kek" {
		t.Fatalf("bare kid name = %q", name)
	}
	if name := kekNameFromKid("https://v/secrets/x"); name != "" {
		t.Fatalf("non-key kid accepted: %q", name)
	}
	do(s.createKey, "POST", "/x", `{"kty":"EC"}`, map[string]string{"name": "eckek"})
	ecBlob := makeBYOKBlob(t, kekPub, "eckek", targetDER)
	if w := do(s.importKey, "PUT", "/x", fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, ecBlob),
		map[string]string{"name": "m6"}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "not an RSA key") {
		t.Fatalf("EC KEK = %d %s", w.Code, w.Body.Bytes())
	}
	short, _ := json.Marshal(map[string]any{
		"schema_version": "1.0.0",
		"header":         map[string]string{"kid": "kek", "alg": "dir", "enc": "CKM_RSA_AES_KEY_WRAP"},
		"ciphertext":     base64.RawURLEncoding.EncodeToString([]byte("tiny")),
	})
	if w := do(s.importKey, "PUT", "/x",
		fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, base64.StdEncoding.EncodeToString(short)),
		map[string]string{"name": "m7"}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "too short") {
		t.Fatalf("short ciphertext = %d %s", w.Code, w.Body.Bytes())
	}
	// A wrapped EC target is refused (BYOK payload must be RSA here).
	ecTarget, _ := x509.MarshalPKCS8PrivateKey(mustEC(t))
	ecPayload := makeBYOKBlob(t, kekPub, "kek", ecTarget)
	if w := do(s.importKey, "PUT", "/x", fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, ecPayload),
		map[string]string{"name": "m8"}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "must be an RSA key") {
		t.Fatalf("EC payload = %d %s", w.Code, w.Body.Bytes())
	}

	// Wrong enc algorithm is refused.
	blob["ciphertext"] = base64.RawURLEncoding.EncodeToString(ct)
	blob["header"] = map[string]string{"kid": "kek", "alg": "dir", "enc": "CKM_AES_KEY_WRAP"}
	wrongEnc, _ := json.Marshal(blob)
	if w := do(s.importKey, "PUT", "/x",
		fmt.Sprintf(`{"key":{"kty":"RSA-HSM","key_hsm":%q}}`, base64.RawURLEncoding.EncodeToString(wrongEnc)),
		map[string]string{"name": "m5"}); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "CKM_RSA_AES_KEY_WRAP") {
		t.Fatalf("wrong enc = %d %s", w.Code, w.Body.Bytes())
	}
}

func TestAESKWPVectors(t *testing.T) {
	// Round-trip both KWP paths (single-block and multi-block) at several
	// payload sizes, including non-multiples of 8.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	for _, size := range []int{1, 7, 8, 9, 16, 20, 32, 1190} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i * 7)
		}
		wrapped := kwpWrap(t, kek, plain)
		got, err := aesKWPUnwrap(kek, wrapped)
		if err != nil {
			t.Fatalf("size %d: unwrap: %v", size, err)
		}
		if string(got) != string(plain) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
		// Corruption is detected.
		wrapped[0] ^= 0xff
		if _, err := aesKWPUnwrap(kek, wrapped); err == nil {
			t.Fatalf("size %d: corrupted wrap accepted", size)
		}
	}
	if _, err := aesKWPUnwrap(kek, []byte("short")); err == nil {
		t.Fatal("short input accepted")
	}
}
