package server_test

// The P0 centerpiece: the REAL Azure SDK (azsecrets + azidentity) completes
// challenge-based authentication against an in-process entra-emulator and
// round-trips secrets — the production trust path, fully offline.
//
// Flow under test:
//   1. azsecrets probes without a token → our 401 challenge advertises
//      entra-emulator's authority.
//   2. azidentity.ClientSecretCredential acquires a vault-audience token
//      from entra (the resource app https://vault.azure.net is registered
//      via entra's admin API, exactly as the docker-compose seeds it).
//   3. The SDK retries with the token; we validate it against entra's JWKS.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/config"
	"github.com/calvinchengx/azure-keyvault-emulator/internal/server"
	entra "github.com/calvinchengx/entra-emulator/emulator"
)

type fixture struct {
	t     *testing.T
	emu   *entra.Emulator
	kv    *httptest.Server
	srv   *server.Server
	creds *azidentity.ClientSecretCredential
}

// combinedTransport routes token traffic to entra's client and everything
// else (the vault) to the httptest client — one Transporter for the SDK.
type combinedTransport struct {
	entraHost string
	entra     *http.Client
	vault     *http.Client
}

func (c *combinedTransport) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host == c.entraHost {
		return c.entra.Do(req)
	}
	return c.vault.Do(req)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	emu := entra.StartT(t, entra.WithTLS())

	// Register the Key Vault resource app so client-credentials scope
	// https://vault.azure.net/.default resolves (the compose-seed step).
	body, _ := json.Marshal(map[string]any{
		"displayName": "Azure Key Vault", "appIdUri": "https://vault.azure.net", "isConfidential": true,
	})
	resp, err := emu.HTTPClient().Post(emu.Origin+"/admin/api/apps", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("seed resource app: %d", resp.StatusCode)
	}

	cfg := &config.Config{
		EntraIssuer:             emu.Origin + "/" + emu.TenantID + "/v2.0",
		DefaultVault:            "emulator",
		SoftDeleteRetentionDays: 90,
	}
	if err := cfg.Finish(); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg, emu.HTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	kv := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(kv.Close)

	transport := &combinedTransport{
		entraHost: strings.TrimPrefix(emu.Origin, "https://"),
		entra:     emu.HTTPClient(),
		vault:     kv.Client(),
	}
	cred, err := azidentity.NewClientSecretCredential(
		emu.TenantID, entra.DaemonClientID, entra.DaemonSecret,
		&azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: emu.Origin},
				Transport: transport,
			},
			DisableInstanceDiscovery: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, emu: emu, kv: kv, srv: srv, creds: cred}
}

// client builds a real azsecrets client against the emulator.
func (f *fixture) client(t *testing.T) *azsecrets.Client {
	t.Helper()
	transport := &combinedTransport{
		entraHost: strings.TrimPrefix(f.emu.Origin, "https://"),
		entra:     f.emu.HTTPClient(),
		vault:     f.kv.Client(),
	}
	c, err := azsecrets.NewClient(f.kv.URL, f.creds, &azsecrets.ClientOptions{
		ClientOptions: policy.ClientOptions{Transport: transport},
		// The vault URL is 127.0.0.1 (httptest), so the SDK's check that the
		// challenge resource matches the vault domain must be relaxed —
		// documented localhost mode. DNS-pinned {name}.vault.azure.net use
		// doesn't need this.
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzureSDKChallengeFlowAndSecretLifecycle(t *testing.T) {
	f := newFixture(t)
	sc := f.client(t)
	ctx := context.Background()

	// Set — the first call walks the full challenge handshake.
	set, err := sc.SetSecret(ctx, "db-password", azsecrets.SetSecretParameters{
		Value:       to.Ptr("hunter2"),
		ContentType: to.Ptr("text/plain"),
		Tags:        map[string]*string{"env": to.Ptr("dev")},
	}, nil)
	if err != nil {
		t.Fatalf("SetSecret via real SDK: %v", err)
	}
	if set.ID == nil || set.ID.Name() != "db-password" || set.ID.Version() == "" {
		t.Fatalf("set id = %v", set.ID)
	}

	// Get current.
	got, err := sc.GetSecret(ctx, "db-password", "", nil)
	if err != nil || *got.Value != "hunter2" || *got.ContentType != "text/plain" {
		t.Fatalf("GetSecret = %v, %v", got.Value, err)
	}
	// New version; old still addressable.
	v1 := set.ID.Version()
	set2, err := sc.SetSecret(ctx, "db-password", azsecrets.SetSecretParameters{Value: to.Ptr("hunter3")}, nil)
	if err != nil || set2.ID.Version() == v1 {
		t.Fatalf("second set: %v (version %s)", err, set2.ID.Version())
	}
	old, err := sc.GetSecret(ctx, "db-password", v1, nil)
	if err != nil || *old.Value != "hunter2" {
		t.Fatalf("old version = %v, %v", old.Value, err)
	}

	// Update properties: disable the old version → gets 403.
	_, err = sc.UpdateSecretProperties(ctx, "db-password", v1, azsecrets.UpdateSecretPropertiesParameters{
		SecretAttributes: &azsecrets.SecretAttributes{Enabled: to.Ptr(false)},
	}, nil)
	if err != nil {
		t.Fatalf("UpdateSecretProperties: %v", err)
	}
	if _, err := sc.GetSecret(ctx, "db-password", v1, nil); err == nil ||
		!strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("disabled get err = %v; want Forbidden", err)
	}

	// List via the pager.
	if _, err := sc.SetSecret(ctx, "api-key", azsecrets.SetSecretParameters{Value: to.Ptr("k")}, nil); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	pager := sc.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatalf("list page: %v", err)
		}
		for _, it := range page.Value {
			names[it.ID.Name()] = true
		}
	}
	if !names["db-password"] || !names["api-key"] {
		t.Fatalf("listed names = %v", names)
	}
	// Versions pager.
	count := 0
	vp := sc.NewListSecretPropertiesVersionsPager("db-password", nil)
	for vp.More() {
		page, err := vp.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		count += len(page.Value)
	}
	if count != 2 {
		t.Fatalf("versions = %d; want 2", count)
	}

	// Backup → delete → purge → restore.
	backup, err := sc.BackupSecret(ctx, "api-key", nil)
	if err != nil || len(backup.Value) == 0 {
		t.Fatalf("backup: %v", err)
	}
	if _, err := sc.DeleteSecret(ctx, "api-key", nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := sc.GetSecret(ctx, "api-key", "", nil); err == nil {
		t.Fatal("deleted secret still readable")
	}
	deleted, err := sc.GetDeletedSecret(ctx, "api-key", nil)
	if err != nil || deleted.ScheduledPurgeDate == nil {
		t.Fatalf("get deleted: %v", err)
	}
	if _, err := sc.PurgeDeletedSecret(ctx, "api-key", nil); err != nil {
		t.Fatalf("purge: %v", err)
	}
	restored, err := sc.RestoreSecret(ctx, azsecrets.RestoreSecretParameters{SecretBackup: backup.Value}, nil)
	if err != nil || *restored.Value != "k" {
		t.Fatalf("restore = %v, %v", restored.Value, err)
	}

	// Delete → recover round trip.
	if _, err := sc.DeleteSecret(ctx, "db-password", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.RecoverDeletedSecret(ctx, "db-password", nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got, err := sc.GetSecret(ctx, "db-password", "", nil); err != nil || *got.Value != "hunter3" {
		t.Fatalf("recovered = %v, %v", got.Value, err)
	}
}

func TestChallengeHeaderShape(t *testing.T) {
	f := newFixture(t)
	// Raw probe: the 401 must advertise entra's real authority.
	resp, err := f.kv.Client().Get(f.kv.URL + "/secrets/x?api-version=7.5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("probe = %d; want 401", resp.StatusCode)
	}
	ch := resp.Header.Get("WWW-Authenticate")
	authority := f.emu.Origin + "/" + f.emu.TenantID
	if !strings.Contains(ch, `authorization="`+authority+`"`) ||
		!strings.Contains(ch, `resource="https://vault.azure.net"`) {
		t.Fatalf("challenge = %q; want authority %q", ch, authority)
	}
}

func TestTokenRejections(t *testing.T) {
	f := newFixture(t)

	// A fabric-audience token (forged via entra) is rejected: wrong audience.
	body, _ := json.Marshal(map[string]any{
		"clientId": entra.DaemonClientID, "audience": "https://api.fabric.microsoft.com",
	})
	resp, err := f.emu.HTTPClient().Post(f.emu.Origin+"/admin/api/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	_ = json.Unmarshal(raw, &tok)
	if tok.AccessToken == "" {
		tok.AccessToken = tok.Token
	}
	req, _ := http.NewRequest("GET", f.kv.URL+"/secrets/x?api-version=7.5", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err = f.kv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("fabric-audience token = %d; want 401", resp.StatusCode)
	}

	// A valid vault token stops working when the vault's clock passes exp.
	sc := f.client(t)
	if _, err := sc.SetSecret(context.Background(), "s", azsecrets.SetSecretParameters{Value: to.Ptr("v")}, nil); err != nil {
		t.Fatal(err)
	}
	f.srv.Clock.Advance(7200) // tokens live 1h
	req2, _ := http.NewRequest("GET", f.kv.URL+"/secrets/s?api-version=7.5", nil)
	// Reuse the SDK's cached token by going raw: mint one fresh, then expire it.
	tk, err := f.creds.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://vault.azure.net/.default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = tk // token minted at entra's real clock; vault's clock is 2h ahead
	req2.Header.Set("Authorization", "Bearer "+tk.Token)
	resp2, err := f.kv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired-by-clock token = %d; want 401", resp2.StatusCode)
	}
}

func TestManagedIdentityPath(t *testing.T) {
	f := newFixture(t)
	// The App Service MSI contract: IDENTITY_ENDPOINT + X-IDENTITY-HEADER,
	// resource echoed as the audience — no secret in the workload.
	req, _ := http.NewRequest("GET",
		f.emu.Origin+"/msi/token?resource=https://vault.azure.net&api-version=2019-08-01", nil)
	req.Header.Set("X-IDENTITY-HEADER", "managed-identity-secret")
	resp, err := f.emu.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("msi mint = %d: %s", resp.StatusCode, raw)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("msi token: %v %s", err, raw)
	}

	// Seed a secret with the SDK, then read it with the MSI token raw.
	sc := f.client(t)
	if _, err := sc.SetSecret(context.Background(), "msi-read", azsecrets.SetSecretParameters{Value: to.Ptr("42")}, nil); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest("GET", f.kv.URL+"/secrets/msi-read?api-version=7.5", nil)
	req2.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp2, err := f.kv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var bundle struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&bundle); err != nil || bundle.Value != "42" {
		t.Fatalf("msi read = %d %+v %v", resp2.StatusCode, bundle, err)
	}
}
