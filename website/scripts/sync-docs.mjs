// Generates Starlight content from the canonical Markdown in /docs, keeping
// /docs as the single source of truth (its files stay pristine and their
// GitHub-relative links keep working). Run automatically before dev/build.
//
// For each docs/NN-name.md it: derives the title from the leading H1, injects
// Starlight frontmatter, drops the duplicate H1, and rewrites intra-doc
// `NN-name.md` links to site routes under the configured base.
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectParity, writeParityHistory, parityManifest } from './parity-versions.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = join(here, '..', '..');
const DOCS_SRC = join(REPO, 'docs');
const OUT = join(here, '..', 'src', 'content', 'docs');
// Must match `base` in astro.config.mjs. The docs sit under /docs/ because
// the site root is the hand-written landing page.
export const BASE = '/azure-keyvault-emulator/docs/';

// Parity version data (release tags + the live map), collected once. `version`
// is e.g. "v0.2.0" on a tag, otherwise "latest-<short sha>".
const PARITY = collectParity(REPO);
const IS_RELEASE = /^v\d+\.\d+\.\d+$/.test(PARITY.version);
// The parity map is the one doc without a reading-order number: it is a living
// reference rather than a chapter, and its URL is just /parity/.
const PARITY_RE = /(^|\/)parity\.md$/;
// Docs are `NN-name.md` chapters, plus the un-numbered parity map.
const DOC_RE = /^(\d{2}-.*|parity)\.md$/;

// Rewrite `](./|docs/ NN-slug.md#anchor)` → `](/azure-keyvault-emulator/docs/NN-slug/#anchor)`.
const LINK_RE = /\]\((?:\.\/|docs\/)?(\d{2}-[a-z0-9-]+|parity)\.md(#[^)]*)?\)/g;
// Repo-relative links (`../docker-compose.yml`) are correct on GitHub, where /docs sits one
// level under the repo root — but they are dead on the site, whose pages are
// served from flat `/<base>/<slug>/` routes with nothing above them. Rewriting
// to an absolute GitHub URL is what keeps ONE source of truth working in both
// renderings, which is this script's whole premise; the alternative is editing
// /docs into something that no longer resolves on GitHub.
//
// `tree` vs `blob` is decided from what the path actually is on disk rather
// than guessed from a trailing slash, and a path that resolves to nothing is
// reported rather than silently linked into a 404.
const REPO_URL = 'https://github.com/calvinchengx/azure-keyvault-emulator';
const REPO_LINK_RE = /\]\(\.\.\/([^)#]+)(#[^)]*)?\)/g;
function rewriteRepoLinks(md, where) {
  return md.replace(REPO_LINK_RE, (_m, path, anchor) => {
    const clean = path.replace(/\/+$/, '');
    const target = join(REPO, clean);
    const exists = existsSync(target);
    if (!exists) {
      console.warn(`sync-docs: WARNING ${where}: ../${path} matches nothing in the repo`);
    }
    const kind = exists && statSync(target).isDirectory() ? 'tree' : 'blob';
    return `](${REPO_URL}/${kind}/main/${clean}${anchor ?? ''})`;
  });
}

function rewriteLinks(md, where = 'docs') {
  const sitewide = md.replace(LINK_RE, (_m, slug, anchor) => `](${BASE}${slug}/${anchor ?? ''})`);
  return rewriteRepoLinks(sitewide, where);
}

// "06 — Secrets" → "Secrets".
function cleanTitle(h1) {
  return h1.replace(/^\d+[a-z]?\s*[—:-]\s*/i, '').trim();
}

// Backslashes must be escaped before quotes, or a title ending in one would
// escape the closing quote and produce unparseable frontmatter.
function yamlEscape(s) {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// Strip the leading H1 (Starlight renders the frontmatter title) and rewrite
// intra-doc links. Shared with the parity snapshot generator so historical
// snapshots convert identically.
function convertBody(raw, where = 'docs') {
  const lines = raw.split('\n');
  const h1Index = lines.findIndex((l) => /^#\s+/.test(l));
  if (h1Index >= 0) {
    lines.splice(h1Index, lines[h1Index + 1]?.trim() === '' ? 2 : 1);
  }
  return rewriteLinks(lines.join('\n').replace(/^\n+/, ''), where);
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
  let body = convertBody(raw, name);
  if (PARITY_RE.test(name)) body = parityStamp() + body;
  // Point "Edit this page" at the real source in /docs (the generated copy
  // under src/content/docs/ is git-ignored), not Starlight's default path.
  const editUrl = `${REPO_URL}/edit/main/docs/${name}`;
  const frontmatter = `---\ntitle: ${yamlEscape(title)}\neditUrl: ${yamlEscape(editUrl)}\n---\n\n`;
  return frontmatter + body;
}

// NO writeIndex() ANY MORE, and this note is here so its absence reads as a
// decision rather than an omission.
//
// The docs root is `website/src/pages/index.astro` now -- the landing page,
// served both at the site root and at the docs base from ONE build output. An
// index.md here would have claimed the same route and collided with it.
//
// Its curated chapter list was not lost: it moved onto that page, under #docs.
// Keeping both is the arrangement fabric-emulator had, where a hand-written
// root page and an Astro page under /docs/ said the same thing separately and
// drifted until one advertised a release that did not exist.

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
const names = readdirSync(DOCS_SRC).filter((n) => DOC_RE.test(n)).sort();
for (const name of names) {
  writeFileSync(join(OUT, name), convert(name));
}
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
