// Real Microsoft JavaScript SDK (@azure/keyvault-*) against the emulator pair.
//
// ClientSecretCredential walks the challenge handshake against a real
// entra-emulator; then SecretClient / KeyClient / CryptographyClient /
// CertificateClient exercise the data plane. Env: KV_URL, AZURE_TENANT_ID,
// AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, ENTRA_AUTHORITY_HOST.
//
// The runner sets NODE_TLS_REJECT_UNAUTHORIZED=0 for this process (self-signed
// emulator TLS — harness only). The vault URL is localhost, not
// *.vault.azure.net, so disableChallengeResourceVerification — the same switch
// real SDK users flip for any non-public vault domain.

import { createHash } from "node:crypto";
import { ClientSecretCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import { KeyClient, CryptographyClient } from "@azure/keyvault-keys";
import { CertificateClient } from "@azure/keyvault-certificates";

const KV_URL = process.env.KV_URL;
let failures = 0;

function check(name, cond, extra = "") {
  if (cond) console.log(`  ok  ${name}`);
  else { console.log(`  FAIL ${name} ${extra}`); failures++; }
}

const cred = new ClientSecretCredential(
  process.env.AZURE_TENANT_ID,
  process.env.AZURE_CLIENT_ID,
  process.env.AZURE_CLIENT_SECRET,
  { authorityHost: process.env.ENTRA_AUTHORITY_HOST, disableInstanceDiscovery: true },
);
const opts = { disableChallengeResourceVerification: true };

// --- Secrets: set → versions → soft delete → recover → purge ---
console.log("SecretClient");
const sc = new SecretClient(KV_URL, cred, opts);
await sc.setSecret("js-e2e", "v1");
const latest = await sc.setSecret("js-e2e", "v2");
check("set/get latest", (await sc.getSecret("js-e2e")).value === "v2");
let versions = 0;
for await (const _ of sc.listPropertiesOfSecretVersions("js-e2e")) versions++;
check("two versions listed", versions === 2, `got ${versions}`);
check("get by version",
  (await sc.getSecret("js-e2e", { version: latest.properties.version })).value === "v2");

await (await sc.beginDeleteSecret("js-e2e")).pollUntilDone();
check("deleted secret visible", (await sc.getDeletedSecret("js-e2e")).name === "js-e2e");
await (await sc.beginRecoverDeletedSecret("js-e2e")).pollUntilDone();
check("recovered", (await sc.getSecret("js-e2e")).value === "v2");
await (await sc.beginDeleteSecret("js-e2e")).pollUntilDone();
await sc.purgeDeletedSecret("js-e2e");
try {
  await sc.getDeletedSecret("js-e2e");
  check("purged is gone", false);
} catch (e) {
  check("purged is gone", e.statusCode === 404, `got ${e.statusCode}`);
}

// --- Keys: real RSA crypto through CryptographyClient ---
console.log("KeyClient + CryptographyClient");
const kc = new KeyClient(KV_URL, cred, opts);
const key = await kc.createRsaKey("js-e2e-rsa", { keySize: 2048 });
check("rsa key created", key.keyType === "RSA");
// key.id carries the canonical https://{vault}.vault.azure.net host (as real
// Key Vault would); CryptographyClient dials the id's host, so hand it the
// same key via the emulator's localhost address instead.
const cc = new CryptographyClient(
  `${KV_URL}/keys/${key.name}/${key.properties.version}`, cred, opts);

const plain = Buffer.from("the js sdk is the oracle");
const enc = await cc.encrypt({ algorithm: "RSA-OAEP", plaintext: plain });
const dec = await cc.decrypt({ algorithm: "RSA-OAEP", ciphertext: enc.result });
check("encrypt/decrypt round-trip", Buffer.compare(dec.result, plain) === 0);

const digest = createHash("sha256").update("sign me").digest();
const sig = await cc.sign("RS256", digest);
check("sign/verify", (await cc.verify("RS256", digest, sig.result)).result === true);
const tampered = createHash("sha256").update("tampered").digest();
check("tampered digest rejected",
  (await cc.verify("RS256", tampered, sig.result)).result === false);

// --- Certificates: self-signed issuance via the LRO poller ---
console.log("CertificateClient");
const certClient = new CertificateClient(KV_URL, cred, opts);
const poller = await certClient.beginCreateCertificate("js-e2e-cert", {
  issuerName: "Self",
  subject: "CN=js-e2e",
  validityInMonths: 12,
});
const cert = await poller.pollUntilDone();
check("self-signed cert issued", cert.name === "js-e2e-cert" && cert.cer?.byteLength > 0);
check("linked key materialised", ["RSA", "EC"].includes((await kc.getKey("js-e2e-cert")).keyType));

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log("js suite: all checks passed");
