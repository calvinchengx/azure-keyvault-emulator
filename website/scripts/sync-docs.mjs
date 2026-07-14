// Generates Starlight content from the canonical Markdown in /docs, keeping
// /docs as the single source of truth (its files stay pristine and their
// GitHub-relative links keep working). Run automatically before dev/build.
//
// For each docs/NN-name.md it: derives the title from the leading H1, injects
// Starlight frontmatter, drops the duplicate H1, and rewrites intra-doc
// `NN-name.md` links to site routes under the configured base.
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectParity, writeParityHistory, parityManifest } from './parity-versions.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = join(here, '..', '..');
const DOCS_SRC = join(REPO, 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
export const BASE = '/azure-keyvault-emulator/';

// Parity version data (release tags + the live map), collected once. `version`
// is e.g. "v0.2.0" on a tag, otherwise "latest-<short sha>".
const PARITY = collectParity(REPO);
const IS_RELEASE = /^v\d+\.\d+\.\d+$/.test(PARITY.version);
// The parity map is the one doc without a reading-order number: it is a living
// reference rather than a chapter, and its URL is just /parity/.
const PARITY_RE = /(^|[/-])parity\.md$/;
// Docs are `NN-name.md` chapters, plus the un-numbered parity map.
const DOC_RE = /^(\d{2}-.*|parity)\.md$/;

// Rewrite `](./|docs/ NN-slug.md#anchor)` → `](/azure-keyvault-emulator/NN-slug/#anchor)`.
const LINK_RE = /\]\((?:\.\/|docs\/)?(\d{2}-[a-z0-9-]+|parity)\.md(#[^)]*)?\)/g;
function rewriteLinks(md) {
  return md.replace(LINK_RE, (_m, slug, anchor) => `](${BASE}${slug}/${anchor ?? ''})`);
}

// "06 — Secrets" → "Secrets".
function cleanTitle(h1) {
  return h1.replace(/^\d+[a-z]?\s*[—:-]\s*/i, '').trim();
}

function yamlEscape(s) {
  return '"' + s.replace(/"/g, '\\"') + '"';
}

// Strip the leading H1 (Starlight renders the frontmatter title) and rewrite
// intra-doc links. Shared with the parity snapshot generator so historical
// snapshots convert identically.
function convertBody(raw) {
  const lines = raw.split('\n');
  const h1Index = lines.findIndex((l) => /^#\s+/.test(l));
  if (h1Index >= 0) {
    lines.splice(h1Index, lines[h1Index + 1]?.trim() === '' ? 2 : 1);
  }
  return rewriteLinks(lines.join('\n').replace(/^\n+/, ''));
}

// The context line at the top of the live parity map. Switching versions is the
// top-nav picker's job (src/components/ParityVersionPicker.astro) — this just
// says which version you're reading.
function parityStamp() {
  const what = IS_RELEASE
    ? `release **${PARITY.version}**`
    : `**${PARITY.version}** (the live tip of \`main\`)`;
  return (
    `_Parity map as of ${what} — tracked by git release tags. ` +
    `See the [version history](${BASE}parity-history/) and [parity changelog](${BASE}parity-history/changelog/)._\n\n`
  );
}

function convert(name) {
  const raw = readFileSync(join(DOCS_SRC, name), 'utf8');
  const h1 = raw.split('\n').find((l) => /^#\s+/.test(l));
  const title = h1 ? cleanTitle(h1.replace(/^#\s+/, '')) : name.replace(/\.md$/, '');
  let body = convertBody(raw);
  if (PARITY_RE.test(name)) body = parityStamp() + body;
  // Point "Edit this page" at the real source in /docs (the generated copy
  // under src/content/docs/ is git-ignored), not Starlight's default path.
  const editUrl = `https://github.com/calvinchengx/azure-keyvault-emulator/edit/main/docs/${name}`;
  const frontmatter = `---\ntitle: ${yamlEscape(title)}\neditUrl: ${yamlEscape(editUrl)}\n---\n\n`;
  return frontmatter + body;
}

function writeIndex() {
  const body = rewriteLinks(
    `Local emulator of the **Azure Key Vault data plane** in a single Go binary — ` +
      `secrets, keys (real RSA/EC cryptography), and certificates (self-signed + PFX/PEM import), ` +
      `with versioning and soft delete on a controllable clock. Unlike pass-through emulators, ` +
      `**authentication is the point**: the 401 challenge advertises a real Entra authority and ` +
      `every token is validated for signature, issuer, vault audience, and expiry against ` +
      `[entra-emulator](https://calvinchengx.github.io/entra-emulator/)'s JWKS — so ` +
      `\`DefaultAzureCredential\` walks the same path it walks in production, and the real ` +
      `\`azsecrets\` / \`azkeys\` / \`azcertificates\` SDKs authenticate against it exactly as ` +
      `against Azure.\n\n` +
      `:::caution\nLocal development tool only — intentionally insecure (self-signed TLS, no real ` +
      `authorization boundary by default). It emulates the data-plane **contract**, not a security ` +
      `boundary. Run it on \`localhost\` only.\n:::\n\n` +
      `## Start here\n\n` +
      `- [Quickstart](01-quickstart.md) — compose up the pair, mint a token, read and write a secret\n` +
      `- [Installation](02-installation.md) — brew, winget, go install, Docker, compose\n` +
      `- [Architecture](03-architecture.md) — the challenge-auth trust model and why it matters\n` +
      `- [Secrets](06-secrets.md) · [Keys](07-keys.md) · [Certificates](08-certificates.md) — the data-plane reference\n` +
      `- [Authentication](09-authentication.md) — the challenge handshake, credential paths, the permission map\n` +
      `- [Testing](10-testing.md) — freeze the clock, inject throttling; [the three-emulator chain](11-family-integration.md)\n` +
      `- [Roadmap](12-roadmap.md) — phases P0–P3 and what's next\n`,
  );
  // The landing page is synthesized here (no /docs source), so it has no
  // "Edit this page" target.
  const frontmatter =
    `---\ntitle: Azure Key Vault Emulator\ndescription: A local emulator of the Azure Key Vault data plane with real challenge-based authentication.\neditUrl: false\n---\n\n`;
  writeFileSync(join(OUT, 'index.md'), frontmatter + body);
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const names = readdirSync(DOCS_SRC).filter((n) => DOC_RE.test(n)).sort();
for (const name of names) {
  writeFileSync(join(OUT, name), convert(name));
}
writeIndex();
const info = writeParityHistory(OUT, PARITY, { convertBody });
// The top-nav picker is an Astro component and can't shell out to git, so hand
// it the same points as a build-time manifest.
const DATA = join(here, '..', 'src', 'data');
mkdirSync(DATA, { recursive: true });
writeFileSync(join(DATA, 'parity-versions.json'), JSON.stringify(parityManifest(PARITY), null, 2) + '\n');
console.log(
  `sync-docs: wrote ${names.length} docs + index to src/content/docs/ ` +
    `(parity ${info.version}; ${info.snapshots.length} tagged snapshot(s))`,
);
