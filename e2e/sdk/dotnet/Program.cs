// Real Microsoft .NET SDK (Azure.Security.KeyVault.*) against the emulator pair.
//
// ClientSecretCredential walks the challenge handshake against a real
// entra-emulator; then SecretClient / KeyClient / CryptographyClient /
// CertificateClient exercise the data plane. Env: KV_URL, AZURE_TENANT_ID,
// AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, ENTRA_AUTHORITY_HOST.
//
// Self-signed emulator TLS: the transport accepts any server certificate
// (harness only). The vault URL is localhost, not *.vault.azure.net, so
// DisableChallengeResourceVerification — the same switch real SDK users flip
// for any non-public vault domain.

using System.Security.Cryptography;
using Azure;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

var kvUrl = new Uri(Environment.GetEnvironmentVariable("KV_URL")!);
int failures = 0;
void Check(string name, bool cond, string extra = "")
{
    if (cond) Console.WriteLine($"  ok  {name}");
    else { Console.WriteLine($"  FAIL {name} {extra}"); failures++; }
}

var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback =
        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
};
var transport = new HttpClientTransport(handler);

var cred = new ClientSecretCredential(
    Environment.GetEnvironmentVariable("AZURE_TENANT_ID"),
    Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"),
    Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"),
    new ClientSecretCredentialOptions
    {
        AuthorityHost = new Uri(Environment.GetEnvironmentVariable("ENTRA_AUTHORITY_HOST")!),
        DisableInstanceDiscovery = true,
        Transport = transport,
    });

// --- Secrets: set → versions → soft delete → recover → purge ---
Console.WriteLine("SecretClient");
var sc = new SecretClient(kvUrl, cred, new SecretClientOptions
{
    Transport = transport,
    DisableChallengeResourceVerification = true,
});
await sc.SetSecretAsync("dn-e2e", "v1");
var latest = (await sc.SetSecretAsync("dn-e2e", "v2")).Value;
Check("set/get latest", (await sc.GetSecretAsync("dn-e2e")).Value.Value == "v2");
int versions = 0;
await foreach (var _ in sc.GetPropertiesOfSecretVersionsAsync("dn-e2e")) versions++;
Check("two versions listed", versions == 2, $"got {versions}");
Check("get by version",
    (await sc.GetSecretAsync("dn-e2e", latest.Properties.Version)).Value.Value == "v2");

await (await sc.StartDeleteSecretAsync("dn-e2e")).WaitForCompletionAsync();
Check("deleted secret visible", (await sc.GetDeletedSecretAsync("dn-e2e")).Value.Name == "dn-e2e");
await (await sc.StartRecoverDeletedSecretAsync("dn-e2e")).WaitForCompletionAsync();
Check("recovered", (await sc.GetSecretAsync("dn-e2e")).Value.Value == "v2");
await (await sc.StartDeleteSecretAsync("dn-e2e")).WaitForCompletionAsync();
await sc.PurgeDeletedSecretAsync("dn-e2e");
try
{
    await sc.GetDeletedSecretAsync("dn-e2e");
    Check("purged is gone", false);
}
catch (RequestFailedException e)
{
    Check("purged is gone", e.Status == 404, $"got {e.Status}");
}

// --- Keys: real RSA crypto through CryptographyClient ---
Console.WriteLine("KeyClient + CryptographyClient");
var kc = new KeyClient(kvUrl, cred, new KeyClientOptions
{
    Transport = transport,
    DisableChallengeResourceVerification = true,
});
var key = (await kc.CreateRsaKeyAsync(new CreateRsaKeyOptions("dn-e2e-rsa") { KeySize = 2048 })).Value;
Check("rsa key created", key.KeyType == KeyType.Rsa);
// key.Id carries the canonical https://{vault}.vault.azure.net host (as real
// Key Vault would); CryptographyClient dials the id's host, so hand it the
// same key via the emulator's localhost address instead.
var cc = new CryptographyClient(
    new Uri(kvUrl, $"keys/{key.Name}/{key.Properties.Version}"),
    cred,
    new CryptographyClientOptions
    {
        Transport = transport,
        DisableChallengeResourceVerification = true,
    });

var plain = System.Text.Encoding.UTF8.GetBytes("the dotnet sdk is the oracle");
var enc = await cc.EncryptAsync(EncryptionAlgorithm.RsaOaep, plain);
var dec = await cc.DecryptAsync(EncryptionAlgorithm.RsaOaep, enc.Ciphertext);
Check("encrypt/decrypt round-trip", plain.SequenceEqual(dec.Plaintext));

var digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("sign me"));
var sig = await cc.SignAsync(SignatureAlgorithm.RS256, digest);
Check("sign/verify", (await cc.VerifyAsync(SignatureAlgorithm.RS256, digest, sig.Signature)).IsValid);
var tampered = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("tampered"));
Check("tampered digest rejected",
    !(await cc.VerifyAsync(SignatureAlgorithm.RS256, tampered, sig.Signature)).IsValid);

// --- Certificates: self-signed issuance via the LRO poller ---
Console.WriteLine("CertificateClient");
var certClient = new CertificateClient(kvUrl, cred, new CertificateClientOptions
{
    Transport = transport,
    DisableChallengeResourceVerification = true,
});
var op = await certClient.StartCreateCertificateAsync(
    "dn-e2e-cert",
    new CertificatePolicy("Self", "CN=dn-e2e") { ValidityInMonths = 12 });
var cert = (await op.WaitForCompletionAsync()).Value;
Check("self-signed cert issued", cert.Name == "dn-e2e-cert" && cert.Cer.Length > 0);
var linked = (await kc.GetKeyAsync("dn-e2e-cert")).Value;
Check("linked key materialised", linked.KeyType == KeyType.Rsa || linked.KeyType == KeyType.Ec);

if (failures > 0)
{
    Console.Error.WriteLine($"{failures} check(s) failed");
    Environment.Exit(1);
}
Console.WriteLine("dotnet suite: all checks passed");
