package server_test

// P1 e2e: the real azkeys SDK drives key lifecycle + cryptography. The
// interop proof: a signature produced by the emulator verifies LOCALLY
// against the public JWK the API returned — real crypto, not stubs.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	entra "github.com/calvinchengx/entra-emulator/emulator"
)

func (f *fixture) keysClient(t *testing.T) *azkeys.Client {
	t.Helper()
	transport := &combinedTransport{
		entraHost: strings.TrimPrefix(f.emu.Origin, "https://"),
		entra:     f.emu.HTTPClient(),
		vault:     f.kv.Client(),
	}
	c, err := azkeys.NewClient(f.kv.URL, f.creds, &azkeys.ClientOptions{
		ClientOptions:                        policy.ClientOptions{Transport: transport},
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzkeysRSALifecycleAndCrypto(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	created, err := kc.CreateKey(ctx, "signer", azkeys.CreateKeyParameters{
		Kty:     to.Ptr(azkeys.KeyTypeRSA),
		KeySize: to.Ptr(int32(2048)),
	}, nil)
	if err != nil {
		t.Fatalf("CreateKey via real SDK: %v", err)
	}
	if created.Key.KID == nil || created.Key.N == nil || created.Key.E == nil {
		t.Fatalf("created key JWK incomplete: %+v", created.Key)
	}

	// Sign a digest through the SDK…
	digest := sha256.Sum256([]byte("attest me"))
	signed, err := kc.Sign(ctx, "signer", "", azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// …verify through the SDK…
	verified, err := kc.Verify(ctx, "signer", "", azkeys.VerifyParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Digest:    digest[:],
		Signature: signed.Result,
	}, nil)
	if err != nil || verified.Value == nil || !*verified.Value {
		t.Fatalf("Verify: %v (value=%v)", err, verified.Value)
	}
	// …and, the interop proof: verify LOCALLY against the returned JWK.
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(created.Key.N),
		E: int(new(big.Int).SetBytes(created.Key.E).Int64()),
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signed.Result); err != nil {
		t.Fatalf("emulator signature does not verify against its own JWK: %v", err)
	}
	// A tampered signature fails.
	bad := append([]byte{}, signed.Result...)
	bad[0] ^= 0xff
	verified, err = kc.Verify(ctx, "signer", "", azkeys.VerifyParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Digest:    digest[:],
		Signature: bad,
	}, nil)
	if err != nil || verified.Value == nil || *verified.Value {
		t.Fatalf("tampered signature verified: %v", err)
	}

	// Encrypt → decrypt round trip (RSA-OAEP-256).
	plaintext := []byte("wrap me")
	enc, err := kc.Encrypt(ctx, "signer", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     plaintext,
	}, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := kc.Decrypt(ctx, "signer", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     enc.Result,
	}, nil)
	if err != nil || string(dec.Result) != string(plaintext) {
		t.Fatalf("Decrypt = %q, %v", dec.Result, err)
	}
	// Wrap/unwrap.
	keyMaterial := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := kc.WrapKey(ctx, "signer", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     keyMaterial,
	}, nil)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	unwrapped, err := kc.UnwrapKey(ctx, "signer", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     wrapped.Result,
	}, nil)
	if err != nil || !bytes.Equal(unwrapped.Result, keyMaterial) {
		t.Fatalf("UnwrapKey: %v", err)
	}

	// Update properties (disable) → crypto ops 403.
	if _, err := kc.UpdateKey(ctx, "signer", created.Key.KID.Version(), azkeys.UpdateKeyParameters{
		KeyAttributes: &azkeys.KeyAttributes{Enabled: to.Ptr(false)},
	}, nil); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if _, err := kc.Sign(ctx, "signer", "", azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256), Value: digest[:],
	}, nil); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("sign with disabled key err = %v; want Forbidden", err)
	}

	// Soft delete → recover; list pager sees the key.
	if _, err := kc.DeleteKey(ctx, "signer", nil); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := kc.RecoverDeletedKey(ctx, "signer", nil); err != nil {
		t.Fatalf("RecoverDeletedKey: %v", err)
	}
	pager := kc.NewListKeyPropertiesPager(nil)
	found := false
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Value {
			if it.KID.Name() == "signer" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("recovered key missing from list")
	}
}

func TestAzkeysECSignVerify(t *testing.T) {
	f := newFixture(t)
	kc := f.keysClient(t)
	ctx := context.Background()

	created, err := kc.CreateKey(ctx, "ec-signer", azkeys.CreateKeyParameters{
		Kty:   to.Ptr(azkeys.KeyTypeEC),
		Curve: to.Ptr(azkeys.CurveNameP256),
	}, nil)
	if err != nil {
		t.Fatalf("CreateKey EC: %v", err)
	}
	digest := sha256.Sum256([]byte("ec attest"))
	signed, err := kc.Sign(ctx, "ec-signer", "", azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmES256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		t.Fatalf("Sign ES256: %v", err)
	}
	// Local verification against the returned JWK (raw r||s signature).
	x := new(big.Int).SetBytes(created.Key.X)
	y := new(big.Int).SetBytes(created.Key.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	half := len(signed.Result) / 2
	r := new(big.Int).SetBytes(signed.Result[:half])
	sv := new(big.Int).SetBytes(signed.Result[half:])
	if !ecdsa.Verify(pub, digest[:], r, sv) {
		t.Fatal("EC signature does not verify against its own JWK")
	}
}

func TestPermissionMap(t *testing.T) {
	f := newFixture(t)
	sc := f.client(t)
	ctx := context.Background()

	if _, err := sc.SetSecret(ctx, "locked", azsecrets.SetSecretParameters{Value: to.Ptr("v1")}, nil); err != nil {
		t.Fatal(err)
	}

	// Restrict the daemon SP (its principal id = the app id in app-only
	// tokens) to secrets/get only.
	perms := map[string][]string{entra.DaemonClientID: {"secrets/get"}}
	raw, _ := json.Marshal(perms)
	resp, err := f.kv.Client().Post(f.kv.URL+"/_emulator/permissions", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, err := sc.GetSecret(ctx, "locked", "", nil); err != nil {
		t.Fatalf("permitted get failed: %v", err)
	}
	if _, err := sc.SetSecret(ctx, "locked", azsecrets.SetSecretParameters{Value: to.Ptr("v2")}, nil); err == nil ||
		!strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("denied set err = %v; want Forbidden", err)
	}

	// Clearing the map restores full access.
	resp, err = f.kv.Client().Post(f.kv.URL+"/_emulator/permissions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := sc.SetSecret(ctx, "locked", azsecrets.SetSecretParameters{Value: to.Ptr("v3")}, nil); err != nil {
		t.Fatalf("set after clearing perms: %v", err)
	}
}
