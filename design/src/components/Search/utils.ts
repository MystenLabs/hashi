// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for turning an Algolia hit into something renderable.
//
// Every field on a hit is untrusted. The four indices behind the search page
// are built by a crawler we do not run, over four sites whose sources take
// outside contributions, and nothing checks what comes back from Algolia. So
// these helpers only ever produce plain text and vetted URLs: the callers hand
// the result to React as children, never to `dangerouslySetInnerHTML`.

const { decode } = require("he");

// InstantSearch HTML-escapes hit values and then wraps query matches in these
// tags, so they are the only markup a highlight value can legitimately hold.
const HIGHLIGHT_PRE_TAG = "<mark>";
const HIGHLIGHT_POST_TAG = "</mark>";

/** Longest label `duplicatedLabel` will consider; keeps its scan linear. */
const MAX_LABEL_LENGTH = 64;

/** A run of hit text, flagged when it is part of the query match. */
export type SnippetPart = { value: string; isHighlighted: boolean };

/**
 * Recover display text from one piece of a highlight value.
 *
 * Two rounds of entity decoding, for the two layers of escaping in play: the
 * one InstantSearch applies to every hit value, and the one already baked into
 * the index, where records store text like "Coin&lt;T&gt;" verbatim. Decoding
 * is safe because the result is rendered as React text — it was pairing it with
 * `dangerouslySetInnerHTML` that turned crawled markup into live markup.
 */
const toDisplayText = (value: string) => decode(decode(value));

/**
 * Split an Algolia `_highlightResult` value into plain-text parts.
 *
 * Splitting on the highlight tags before decoding keeps a `<mark>` the page
 * itself contained from passing as a highlight.
 */
function parseHighlightedValue(value: string): SnippetPart[] {
  const parts: SnippetPart[] = [];
  const push = (text: string, isHighlighted: boolean) => {
    if (text) parts.push({ value: toDisplayText(text), isHighlighted });
  };

  const [head, ...tail] = value.split(HIGHLIGHT_PRE_TAG);
  push(head, false);
  for (const segment of tail) {
    const end = segment.indexOf(HIGHLIGHT_POST_TAG);
    if (end === -1) {
      push(segment, true);
      continue;
    }
    push(segment.slice(0, end), true);
    push(segment.slice(end + HIGHLIGHT_POST_TAG.length), false);
  }
  return parts;
}

/** Truncate `parts` to `maxChars`, cutting at a word boundary. */
function truncateParts(parts: SnippetPart[], maxChars: number): SnippetPart[] {
  const text = parts.map((part) => part.value).join("");
  if (text.length <= maxChars) return parts;

  // Fall back to a hard cut for text with no space to break on.
  const lastSpace = text.lastIndexOf(" ", maxChars);
  const cut = lastSpace > 0 ? lastSpace : maxChars;

  const truncated: SnippetPart[] = [];
  let kept = 0;
  for (const part of parts) {
    if (kept >= cut) break;
    const value = part.value.slice(0, cut - kept);
    truncated.push({ ...part, value });
    kept += value.length;
  }
  truncated.push({ value: "…", isHighlighted: false });
  return truncated;
}

/** Build the excerpt shown under a hit from its highlighted `content`. */
export function getSnippetParts(
  value: string,
  maxChars: number,
): SnippetPart[] {
  return truncateParts(parseHighlightedValue(value), maxChars);
}

/**
 * Parse a hit URL, rejecting anything that is not an http(s) link.
 *
 * Hit URLs are crawled content: a `javascript:` URL reaching an `href` runs on
 * click, and a malformed one throws out of `new URL` and takes the whole result
 * list down with it.
 */
export function parseHitUrl(url: unknown): URL | null {
  if (typeof url !== "string") return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? parsed
      : null;
  } catch {
    return null;
  }
}

const isAsciiUpper = (char: string) => char >= "A" && char <= "Z";

/**
 * If `word` is a glossary label repeated twice and run together with the start
 * of its definition ("MoveMoveAn open source…"), return the label.
 *
 * Candidate labels are tried longest-first and are length-capped, so a word of
 * n characters costs at most 32n comparisons. The backreference this replaces,
 * `/(\b\w{2,})\1[A-Z][^.]*\.\s?/`, backtracks quadratically over a long word.
 */
function duplicatedLabel(word: string): string | null {
  // A match needs the label twice plus the capital that opens the definition.
  const longest = Math.min(MAX_LABEL_LENGTH, (word.length - 1) >> 1);
  for (let length = longest; length >= 2; length--) {
    if (!isAsciiUpper(word[2 * length])) continue;
    const label = word.slice(0, length);
    if (word.startsWith(label, length)) return label;
  }
  return null;
}

/**
 * Strip tooltip text injected by the Algolia crawler.
 *
 * `<Term>` renders a glossary label and its definition into hidden markup, and
 * the crawler concatenates the lot into the indexed text:
 *   "Create, build, and test a MoveMoveAn open source programming language
 *    used for all activity on Sui. project"
 * The label appears twice, immediately followed by a definition that runs to
 * the first period. Keep the label, drop the duplicate and the definition.
 */
export function cleanTooltipText(text: string): string {
  // Zero-width spaces (&#8203;) come from the heading anchors.
  const input = text.replace(/\u200B/g, "");

  const words = /\w+/g;
  let cleaned = "";
  let kept = 0; // how much of `input` has been consumed into `cleaned`

  for (let word = words.exec(input); word; word = words.exec(input)) {
    const label = duplicatedLabel(word[0]);
    if (!label) continue;

    const period = input.indexOf(".", word.index + 2 * label.length);
    if (period === -1) continue;

    const resume = /\s/.test(input[period + 1] ?? "") ? period + 2 : period + 1;
    cleaned += input.slice(kept, word.index) + label + " ";
    kept = resume;
    words.lastIndex = resume;
  }

  return (cleaned + input.slice(kept)).trim();
}

export function getDeepestHierarchyLabel(hierarchy) {
  const levels = ["lvl0", "lvl1", "lvl2", "lvl3", "lvl4", "lvl5", "lvl6"];
  let lastValue = null;

  for (const lvl of levels) {
    const value = hierarchy[lvl];
    if (value == null) {
      break;
    }
    lastValue = value;
  }

  return lastValue || hierarchy.lvl6 || "";
}

/**
 * Build an ordered breadcrumb array from a DocSearch hierarchy object.
 * Deduplicates adjacent identical levels (e.g. lvl0 === lvl1).
 * Strips crawler tooltip artefacts from each level.
 */
export function getHierarchyBreadcrumbs(hierarchy): string[] {
  if (!hierarchy) return [];
  const levels = ["lvl0", "lvl1", "lvl2", "lvl3", "lvl4", "lvl5", "lvl6"];
  const crumbs: string[] = [];
  for (const lvl of levels) {
    const raw = hierarchy[lvl];
    if (raw == null) break;
    const value = cleanTooltipText(raw);
    if (crumbs.length === 0 || crumbs[crumbs.length - 1] !== value) {
      crumbs.push(value);
    }
  }
  return crumbs;
}
