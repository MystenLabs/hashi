// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Postbuild: emit a .md version of every page next to its .html so AI agents
// (and any client honoring the agentdocsspec.com convention) can fetch the
// raw markdown directly. Each /<slug>.html page gets a sibling /<slug>.md.
//
// Mirrors the markdown-export pattern used by the Sui docs:
// https://github.com/MystenLabs/sui/blob/main/docs/site/scripts/copy-markdown-files.js
// — but stripped down because the hashi docs do not use <ImportContent> or
// snippets yet.

const fs = require("fs");
const path = require("path");
const matter = require("gray-matter");

const SITE_ROOT = path.resolve(__dirname, "..");
const DOCS_DIR = path.join(SITE_ROOT, "docs");
const BUILD_DIR = path.join(SITE_ROOT, "build");

function cleanForMarkdown(raw, frontMatter) {
  let body = raw;

  // Drop MDX imports/exports.
  body = body.replace(/^\s*import\s+.*?from\s+['"].*?['"];?\s*$/gm, "");
  body = body.replace(/^\s*export\s+(default\s+)?.*$/gm, "");

  // Drop MDX comments `{/* ... */}`.
  body = body.replace(/\{\/\*[\s\S]*?\*\/\}/g, "");

  // Strip the few raw <div style={{ ... }}>...</div> wrappers that exist
  // in user-flows.mdx — keep their inner content.
  body = body.replace(/<div\s+style=\{\{[^}]+\}\}>/g, "");
  body = body.replace(/<\/div>/g, "");

  // Drop solo JSX self-closing tags (none today, defensive).
  body = body.replace(/<[A-Z][A-Za-z0-9]*\b[^>]*\/>/g, "");

  // Collapse any double-blank-line runs left over.
  body = body.replace(/\n{3,}/g, "\n\n");

  let header = "";
  if (frontMatter?.title) {
    header = `# ${frontMatter.title}\n\n`;
  }
  // Markdown llms.txt directive — agents fetching `.md` URLs discover the
  // index from this line. Mirrors the Sui docs convention:
  // https://agentdocsspec.com/spec/#llms-txt-directive-md
  header +=
    "*[Documentation index](/hashi/design/llms.txt) · " +
    "[Full index](/hashi/design/llms-full.txt)*\n\n";
  if (frontMatter?.description) {
    header += `> ${frontMatter.description}\n\n`;
  }

  return header + body.trim() + "\n";
}

function emit(slug, markdown) {
  const outFile =
    slug === ""
      ? path.join(BUILD_DIR, "index.md")
      : path.join(BUILD_DIR, `${slug}.md`);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, markdown, "utf8");
}

function listPages(dir, prefix) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith(".") || e.name.startsWith("_")) continue;
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) {
      if (rel !== "snippets") out.push(...listPages(path.join(dir, e.name), rel));
    } else if (e.isFile() && e.name.endsWith(".mdx")) {
      out.push(rel);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(BUILD_DIR)) {
    console.error(
      `[copy-markdown-files] build/ not found at ${BUILD_DIR}. Run \`npm run build\` first.`,
    );
    process.exit(1);
  }

  // Walk docs/ recursively so nested pages (validators/, hbtc/, reference/)
  // get a .md copy too. snippets/ holds partials, not pages.
  const files = listPages(DOCS_DIR, "");

  let count = 0;
  for (const rel of files) {
    const filePath = path.join(DOCS_DIR, rel);
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = matter(raw);
    const md = cleanForMarkdown(parsed.content, parsed.data);

    // README.mdx is mounted at the docs root (slug: /).
    const slug =
      rel === "README.mdx"
        ? ""
        : rel.replace(/\.mdx$/, "");
    emit(slug, md);
    count += 1;
  }

  console.log(`[copy-markdown-files] wrote ${count} .md files into ${BUILD_DIR}`);
}

main();
