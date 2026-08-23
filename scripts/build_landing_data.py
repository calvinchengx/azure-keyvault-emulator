#!/usr/bin/env python3
"""Publish the landing page's numbers, and refuse to publish a page that types them.

site/index.html is hand-written and Astro never sees it, so none of the checks
that protect the docs protect it. The specific way a front page goes wrong is
not a broken tag: it is a number that was true when someone typed it. This
repository's own README shows the failure already, its parity summary having
been written by hand and left behind by the ledger it summarises.

So the page carries no numbers at all. It carries placeholders, and this
script:

  1. derives every one of them from docs/parity.md (which grades the rows) and
     docs/witnesses.json (which names the evidence, ranked ci: > sdk: > go:),
  2. writes them to <out>/landing-data.json beside the page, and copies the
     witness manifest verbatim to <out>/parity-witnesses.json so a reader can
     audit the derivation against its source,
  3. FAILS if the page has stopped being bound to any of it.

The failure modes it exists for, each of which is silent:

  hardcoded    a placeholder whose content is a digit, or a stat tile with no
               placeholder at all. Either one is a number that will rot.
  unbound      a placeholder the page's script no longer fills, or a derived
               key the script no longer reads. The em dash then ships.
  unread       a manifest that yielded nothing, or two manifests that disagree
               about how many claims exist. A derivation over zero rows is
               indistinguishable from a clean run.
  unresolved   a relative link that lands nowhere in the assembled tree. The
               docs sit under docs/ and the landing page sits above them, so
               every link across that seam is a base-path assumption.

Usage:
    build_landing_data.py --out DIR            derive, copy, and check the page
    build_landing_data.py --out DIR --site DIR also resolve the page's links
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PARITY = ROOT / "docs" / "parity.md"
WITNESSES = ROOT / "docs" / "witnesses.json"
LANDING = ROOT / "site" / "index.html"

DATA_NAME = "landing-data.json"
MANIFEST_COPY = "parity-witnesses.json"

# Sections of parity.md that make no capability claim: the legend, the
# conformance table (itself a list of witnesses), the emulator-only helpers,
# and the explicit scope boundary. Kept in step with check_witnesses.py, which
# grades the same table for the same reason.
SKIP_SECTIONS = {
    "Ecosystem conformance: real clients as witnesses",
    "Emulator-only (no Key Vault equivalent — these exist for testing)",
    "Legend",
    "Scope boundary: the vault, not the infrastructure around it",
}
BOUNDARY_SECTION = "Scope boundary: the vault, not the infrastructure around it"

GRADES = {"\U0001F7E2": "real", "\U0001F7E1": "emulated",
          "\U0001F7E0": "byo-engine", "\U0001F534": "not-implemented"}

# Strongest first. A claim is credited once, by its best witness, so the tiers
# partition the ledger instead of double-counting a claim that carries five.
TIERS = ("ci", "sdk", "go", "boundary")

# Every id the page must carry as an unfilled placeholder, and the script must
# fill. Adding a stat tile without adding it here is caught by STAT_RE below.
REQUIRED_IDS = (
    "green-count", "ci-count", "ci-count-2", "sdk-count", "sdk-count-2",
    "go-count", "go-count-2", "go-count-3", "go-count-4",
    "job-count", "scope-count", "partial-count", "go-only-claims",
)

# Top-level keys of landing-data.json the page must still be reading. A page
# that stops reading one has stopped being bound to that manifest.
REQUIRED_KEYS = ("claims", "by_tier", "grades", "out_of_scope", "ci_jobs", "go_only")

# A placeholder is an element carrying one of the ids above whose content is
# the em dash entity and nothing else. `(?s)` because the markup wraps.
PLACEHOLDER_RE = r'<(?:b|span)[^>]*\bid="{id}"[^>]*>(.*?)</(?:b|span)>'
# The stat strip, and the <b> elements inside it.
# The strip runs to the end of the hero; a lazy match to the next </div>
# would stop at the first tile and check one sixth of the row.
STATS_RE = re.compile(r'<div class="stats">(.*?)</header>', re.S)
STAT_B_RE = re.compile(r"<b\b([^>]*)>(.*?)</b>", re.S)
ID_ATTR_RE = re.compile(r'\bid="([^"]+)"')
ID_RE = re.compile(r'\sid="([^"]+)"')
REF_RE = re.compile(r'(?:href|src)="([^"]+)"')
FETCH_RE = re.compile(r"fetch\('([^']+)'\)")
EXTERNAL = ("http://", "https://", "mailto:", "data:", "//")


# --------------------------------------------------------------------------
# derivation


def parity_rows() -> tuple[dict[str, int], int]:
    """Grade counts over the capability sections, plus the boundary rows.

    Rows are counted as TABLE ROWS in a known section, never by grepping for
    the emoji: the prose above each table explains what the marks mean and
    uses them, which is how a count comes out plausible and wrong.
    """
    counts = {name: 0 for name in GRADES.values()}
    boundary = 0
    section = None
    for line in PARITY.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or section is None:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or set(cells[0]) <= set("-"):
            continue
        mark = next((m for m in GRADES if m in cells[-1]), None)
        if mark is None:
            continue
        if section == BOUNDARY_SECTION:
            boundary += 1
            continue
        if section in SKIP_SECTIONS:
            continue
        counts[GRADES[mark]] += 1
    return counts, boundary


def derive() -> dict:
    grades, boundary_rows = parity_rows()
    manifest = json.loads(WITNESSES.read_text(encoding="utf-8"))

    by_tier = {t: 0 for t in TIERS}
    ci_jobs: set[str] = set()
    go_only: list[str] = []
    for entry in manifest.values():
        witnesses = entry.get("witnesses", [])
        kinds = {w.split(":", 1)[0] for w in witnesses}
        ci_jobs.update(w.split(":", 1)[1] for w in witnesses if w.startswith("ci:"))
        best = next((t for t in TIERS if t in kinds), None)
        if best is None:
            raise SystemExit(f"FAIL: {entry.get('claim')!r} names no usable witness")
        by_tier[best] += 1
        if best == "go":
            # Stripped of markdown so the page can print them as prose.
            go_only.append(re.sub(r"[*`_]", "", entry.get("claim", "")).strip())

    # The two manifests must agree about how many claims exist. If parity.md
    # grows a green row that witnesses.json has not heard of, the tiers on the
    # page would silently stop adding up to the ledger.
    claims = grades["real"]
    if claims != len(manifest):
        raise SystemExit(
            f"FAIL: docs/parity.md has {claims} rows graded real and "
            f"docs/witnesses.json has {len(manifest)} entries. The page's tier "
            "counts only partition the ledger while those agree."
        )
    if claims == 0 or not manifest:
        raise SystemExit("FAIL: read no claims at all. A derivation over zero "
                         "rows proves nothing and would publish an empty page.")
    # The scope boundary is its own table and its own claim on the page:
    # "out of scope" is a decision, where a capability-section red row would
    # be an omission. Counted separately so the page cannot conflate them.
    if boundary_rows == 0:
        raise SystemExit("FAIL: read no out-of-scope rows. The honest half of "
                         "the page would be blank.")

    return {
        "claims": claims,
        "by_tier": by_tier,
        "grades": grades,
        "out_of_scope": boundary_rows,
        "ci_jobs": len(ci_jobs),
        "ci_job_names": sorted(ci_jobs),
        "go_only": sorted(go_only),
        "source": {"parity": "docs/parity.md", "witnesses": "docs/witnesses.json"},
    }


# --------------------------------------------------------------------------
# the page holds up


def check_page(html: str, data: dict, failures: list[str]) -> None:
    if f"fetch('{DATA_NAME}')" not in html:
        failures.append(f"the page no longer fetches {DATA_NAME}; nothing would fill it")

    for key in REQUIRED_KEYS:
        if key not in data:
            failures.append(f"landing-data.json has no {key!r}")
        if f"d.{key}" not in html and f"d['{key}']" not in html:
            failures.append(f"the page never reads d.{key}; it has stopped "
                            f"reading that manifest")

    for ident in REQUIRED_IDS:
        found = re.search(PLACEHOLDER_RE.format(id=re.escape(ident)), html, re.S)
        if not found:
            failures.append(f"no placeholder element carries id={ident!r}")
            continue
        body = found.group(1).strip()
        if body != "&mdash;":
            failures.append(
                f"id={ident!r} contains {body[:40]!r} rather than the em dash "
                "placeholder. A number written into the markup is a number "
                "nothing will update."
            )
        if f"'{ident}'" not in html:
            failures.append(f"id={ident!r} is never filled by the page's script")

    # Any <b> in the stat strip that is not one of the placeholders above is a
    # hardcoded headline number, whether or not it happens to be right today.
    stats = STATS_RE.search(html)
    if not stats:
        failures.append("the stat strip could not be found; STATS_RE has stopped matching")
    else:
        tiles = STAT_B_RE.findall(stats.group(1))
        if not tiles:
            failures.append("the stat strip contains no tiles at all")
        for attrs, body in tiles:
            ident = ID_ATTR_RE.search(attrs)
            if ident is None or ident.group(1) not in REQUIRED_IDS:
                failures.append(
                    f"a stat tile reads {body.strip()[:40]!r} with no bound "
                    "placeholder. Every headline number is read from a manifest."
                )


def check_links(site: pathlib.Path, html: str, failures: list[str]) -> tuple[int, int]:
    """Every relative reference resolves inside the assembled tree.

    The docs live under docs/ and this page sits above them, so each link
    across that seam encodes the Astro base path. Getting it wrong publishes a
    404 and nothing else notices.
    """
    ids = set(ID_RE.findall(html))
    checked = anchors = 0

    def resolve(target: str) -> pathlib.Path:
        clean = target.split("#", 1)[0].split("?", 1)[0]
        clean = clean[2:] if clean.startswith("./") else clean
        if clean in ("", "/"):
            return site / "index.html"
        path = site / clean.lstrip("/")
        return path / "index.html" if clean.endswith("/") else path

    for ref in REF_RE.findall(html) + FETCH_RE.findall(html):
        if ref.startswith(EXTERNAL):
            continue
        if ref.startswith("#"):
            anchors += 1
            if ref[1:] not in ids:
                failures.append(f"anchor {ref} names no id on the page")
            continue
        checked += 1
        landing = resolve(ref)
        if not landing.exists():
            failures.append(f"{ref} -> {landing.relative_to(site)} does not exist")
        if "#" in ref and landing == site / "index.html":
            anchors += 1
            frag = ref.split("#", 1)[1]
            if frag and frag not in ids:
                failures.append(f"anchor #{frag} names no id on the page")

    # A checker that matched nothing is not a passing checker.
    if checked == 0:
        failures.append("no relative links were found at all; REF_RE has stopped matching")
    if anchors == 0:
        failures.append("no same-page anchors were found at all; the nav should have several")
    return checked, anchors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True,
                    help="directory to write landing-data.json into, beside the page")
    ap.add_argument("--site",
                    help="the assembled site root, if the page's links should resolve too")
    args = ap.parse_args()

    data = derive()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / DATA_NAME).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(WITNESSES, out / MANIFEST_COPY)

    html = LANDING.read_text(encoding="utf-8")
    failures: list[str] = []
    check_page(html, data, failures)

    links = anchors = 0
    if args.site:
        site = pathlib.Path(args.site).resolve()
        served = site / "index.html"
        if not served.is_file():
            failures.append(f"{served} does not exist; the page was never copied in")
        elif served.read_text(encoding="utf-8") != html:
            failures.append(f"{served} differs from {LANDING}; something rewrote it")
        else:
            links, anchors = check_links(site, html, failures)

    if failures:
        print("FAIL: the landing page is not bound to its manifests:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    tiers = data["by_tier"]
    print(f"landing data: {data['claims']} claims "
          f"(ci {tiers['ci']}, sdk {tiers['sdk']}, go {tiers['go']}), "
          f"{data['ci_jobs']} CI jobs, "
          f"{data['out_of_scope']} out of scope "
          f"-> {out / DATA_NAME}")
    if args.site:
        print(f"landing page: {links} relative link(s) and {anchors} anchor(s) resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
