// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Imports the README from MystenLabs/hashi-ts-sdk and formats it into a
// Docusaurus page at docs/ts-sdk.mdx.
//
// Usage:
//   node scripts/fetch-sdk-readme.js
//
// hashi-ts-sdk is a PUBLIC repo, so the README is fetched anonymously over HTTPS
// — no GitHub token or `gh` CLI needed. If the fetch fails (offline build, a
// transient network/GitHub error), the script logs a notice and leaves the
// existing committed docs/ts-sdk.mdx in place, so builds never break. Because of
// that the generated file IS committed and serves as the offline fallback; the
// .github/workflows/refresh-sdk-docs.yml workflow keeps it fresh automatically
// (nightly + on SDK release), and you can rerun this script by hand
// (npm run fetch-sdk-readme, from design/) any time.
//
// Formatting applied to the raw README markdown:
//   - drops the leading H1 (the title comes from front matter instead)
//   - derives the page description from the first prose paragraph
//   - converts GitHub alerts (`> [!WARNING]`) to Docusaurus admonitions
//   - rewrites any relative links/images to absolute hashi-ts-sdk URLs
//   - wraps everything in Docusaurus front matter + an AUTO-GENERATED banner
// The source README must stay MDX-friendly (no bare `<` / `{` outside code
// fences); fenced code blocks are passed through untouched.

const fs = require("fs");
const path = require("path");

const REPO = "MystenLabs/hashi-ts-sdk";
const BRANCH = "main";
const REPO_BLOB = `https://github.com/${REPO}/blob/${BRANCH}`;
const REPO_RAW = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const README_URL = `${REPO_RAW}/README.md`;

const SITE_ROOT = path.resolve(__dirname, ".."); // design/
const OUT_FILE = path.join(SITE_ROOT, "docs/ts-sdk.mdx");

const ALERT_ADMONITION = {
  NOTE: "note",
  TIP: "tip",
  IMPORTANT: "info",
  WARNING: "warning",
  CAUTION: "danger",
};

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

async function fetchReadme() {
  // hashi-ts-sdk is public, so the raw README is fetchable anonymously.
  const res = await fetch(README_URL, {
    headers: { "User-Agent": "hashi-docs-fetch-sdk-readme" },
  });
  if (!res.ok) {
    throw new Error(`GET ${README_URL} responded ${res.status} ${res.statusText}`);
  }
  return await res.text();
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

const stripMarkdown = (s) =>
  s
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1") // links / images -> text
    .replace(/[`*_>#]/g, "")
    .replace(/\s+/g, " ")
    .trim();

// Run `fn` over the prose, leaving fenced code blocks (odd-indexed parts) alone.
function transformProse(body, fn) {
  return body
    .split(/(```[\s\S]*?```)/g)
    .map((part, i) => (i % 2 === 1 ? part : fn(part)))
    .join("");
}

function rewriteRelativeLinks(text) {
  return text.replace(/(!?)\[([^\]]*)\]\(([^)]+)\)/g, (match, bang, label, url) => {
    const u = url.trim();
    // Leave absolute URLs, anchors, mailto, and protocol-relative links alone.
    if (/^(https?:|mailto:|#|\/\/)/i.test(u)) return match;
    const base = bang ? REPO_RAW : REPO_BLOB;
    const clean = u.replace(/^\.\//, "").replace(/^\//, "");
    return `${bang}[${label}](${base}/${clean})`;
  });
}

// `> [!WARNING]` blocks -> `:::warning ... :::` admonitions.
function convertAlerts(text) {
  const lines = text.split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/i.exec(lines[i]);
    if (!m) {
      out.push(lines[i]);
      continue;
    }
    const admonition = ALERT_ADMONITION[m[1].toUpperCase()];
    const content = [];
    let j = i + 1;
    for (; j < lines.length && /^>\s?/.test(lines[j]); j++) {
      content.push(lines[j].replace(/^>\s?/, ""));
    }
    out.push("", `:::${admonition}`, "", ...content, "", ":::", "");
    i = j - 1;
  }
  return out.join("\n");
}

function deriveDescription(body) {
  for (const block of body.split(/\n\s*\n/)) {
    const t = block.trim();
    if (!t) continue;
    if (/^!?\[!?\[/.test(t)) continue; // badge block
    if (/^#{1,6}\s/.test(t)) continue; // heading
    if (/^>/.test(t)) continue; // blockquote / alert
    return stripMarkdown(t);
  }
  return "TypeScript SDK for the Hashi protocol.";
}

function format(readme) {
  let body = readme.replace(/\r\n?/g, "\n");

  // Drop the leading H1 — Docusaurus renders the title from front matter.
  body = body.replace(/^\s*#\s+.*\n/, "");

  const description = deriveDescription(body);

  // Strip the leading badge block (consecutive shield/CI image-link lines).
  // They're README furniture, and the CI badge points at the private repo's
  // Actions endpoint, which 404s as a broken image for anonymous viewers.
  body = body.replace(/^(?:\s*\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)\s*\n)+/, "");

  body = transformProse(body, (prose) => convertAlerts(rewriteRelativeLinks(prose)));
  body = body.replace(/\n{3,}/g, "\n\n").trim();

  const frontMatter = [
    "---",
    "title: TypeScript SDK",
    `description: ${JSON.stringify(description)}`,
    "keywords: [ Hashi, TypeScript, SDK, hBTC, deposit, withdrawal, Sui, Bitcoin ]",
    "sidebar_label: TypeScript SDK",
    "---",
  ].join("\n");

  const banner =
    `{/* AUTO-GENERATED from ${REPO} README — do not edit by hand. */}\n` +
    `{/* Refresh with: npm run fetch-sdk-readme (from design/). */}`;

  return `${frontMatter}\n\n${banner}\n\n${body}\n`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`📥 fetch-sdk-readme: importing ${REPO}@${BRANCH} README`);

  try {
    const readme = await fetchReadme();
    fs.writeFileSync(OUT_FILE, format(readme), "utf8");
    console.log(`✅ fetch-sdk-readme: wrote ${path.relative(SITE_ROOT, OUT_FILE)}`);
  } catch (err) {
    if (fs.existsSync(OUT_FILE)) {
      console.warn(
        `⚠️  fetch-sdk-readme: fetch failed (${err.message}); keeping committed docs/ts-sdk.mdx`,
      );
    } else {
      console.warn(`⚠️  fetch-sdk-readme: fetch failed (${err.message}); no fallback file.`);
    }
  }
}

main();
