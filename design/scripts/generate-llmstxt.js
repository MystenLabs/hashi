// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Postbuild: emit /llms.txt and /llms-full.txt at the site root following
// the agentdocsspec.com convention. Mirrors the Sui docs' static llms.txt
// shape: a markdown index of every page where each link points to the .md
// version of that page (so an agent can crawl the doc tree without parsing
// HTML).
//
// /llms.txt        — slim index, grouped by sidebar section.
// /llms-full.txt   — index plus every page's full body inline.

const fs = require("fs");
const path = require("path");
const matter = require("gray-matter");

const SITE_ROOT = path.resolve(__dirname, "..");
const DOCS_DIR = path.join(SITE_ROOT, "docs");
const BUILD_DIR = path.join(SITE_ROOT, "build");
const SITE_URL = "https://mystenlabs.github.io/hashi/design";

const HEADER =
  "# Hashi Documentation for LLMs\n" +
  "\n" +
  "> Design specification for Hashi, the Sui native Bitcoin orchestrator.\n" +
  "> Hashi secures and manages BTC for use on Sui through threshold cryptography,\n" +
  "> minting `hBTC` against committee-approved Bitcoin deposits.\n";

// Sidebar grouping (mirrors design/sidebars.js so the output matches the
// human-facing docs navigation).
const SECTIONS = [
  { label: null, items: ["README", "user-flows"] },
  {
    label: "Design",
    items: [
      "committee",
      "governance-actions",
      "sanctions",
      "service",
      "mpc-protocol",
      "guardian",
      "address-scheme",
      "limiter",
      "fees",
      "config",
    ],
  },
  {
    label: "Flows",
    items: ["reconfiguration", "deposit", "withdraw"],
  },
];

function readDoc(slug) {
  const fileName = slug === "README" ? "README.mdx" : `${slug}.mdx`;
  const filePath = path.join(DOCS_DIR, fileName);
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf8");
  return matter(raw);
}

function urlFor(slug) {
  if (slug === "README") return `${SITE_URL}/index.md`;
  return `${SITE_URL}/${slug}.md`;
}

function indexEntry(slug) {
  const doc = readDoc(slug);
  if (!doc) return null;
  const title = doc.data.title || slug;
  const description = doc.data.description || "";
  return `- [${title}](${urlFor(slug)})${description ? `: ${description}` : ""}`;
}

function buildIndex({ withFullBodies }) {
  let out = HEADER + "\n";
  if (!withFullBodies) {
    out +=
      "> For the complete, unabridged content of every page see " +
      `[llms-full.txt](${SITE_URL}/llms-full.txt).\n\n`;
  } else {
    out += "\n";
  }

  for (const section of SECTIONS) {
    if (section.label) out += `## ${section.label}\n\n`;
    for (const slug of section.items) {
      const line = indexEntry(slug);
      if (line) out += line + "\n";
    }
    out += "\n";
  }

  if (withFullBodies) {
    out += "---\n\n";
    for (const section of SECTIONS) {
      for (const slug of section.items) {
        const doc = readDoc(slug);
        if (!doc) continue;
        const title = doc.data.title || slug;
        out += `## ${title}\n\n`;
        out += `Source: ${urlFor(slug)}\n\n`;
        if (doc.data.description) out += `> ${doc.data.description}\n\n`;
        // Use the same cleanup the .md exporter applies, lite version: just
        // strip MDX imports/exports — keep markdown body intact.
        let body = doc.content
          .replace(/^\s*import\s+.*?from\s+['"].*?['"];?\s*$/gm, "")
          .replace(/^\s*export\s+(default\s+)?.*$/gm, "")
          .replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
          .replace(/\n{3,}/g, "\n\n")
          .trim();
        out += body + "\n\n---\n\n";
      }
    }
  }

  return out;
}

function main() {
  if (!fs.existsSync(BUILD_DIR)) {
    console.error(
      `[generate-llmstxt] build/ not found. Run \`npm run build\` first.`,
    );
    process.exit(1);
  }

  const slim = buildIndex({ withFullBodies: false });
  const full = buildIndex({ withFullBodies: true });

  fs.writeFileSync(path.join(BUILD_DIR, "llms.txt"), slim, "utf8");
  fs.writeFileSync(path.join(BUILD_DIR, "llms-full.txt"), full, "utf8");

  console.log(
    `[generate-llmstxt] wrote llms.txt (${slim.length} bytes) and llms-full.txt (${full.length} bytes)`,
  );
}

main();
