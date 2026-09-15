// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

const { decode } = require("he");

/** Longest label `duplicatedLabel` will consider; keeps its scan linear. */
const MAX_LABEL_LENGTH = 64;

// InstantSearch escapes hit values before wrapping matches in these tags, so
// split on them before decoding, or a "<mark>" in the page text would highlight.
const HIGHLIGHT_PRE_TAG = "<mark>";
const HIGHLIGHT_POST_TAG = "</mark>";

const isAsciiUpper = (char: string) => char >= "A" && char <= "Z";

/** Returns "Move" for "MoveMoveAn": a label written twice, then a capital. */
function duplicatedLabel(word: string): string | null {
  const longest = Math.min(MAX_LABEL_LENGTH, (word.length - 1) >> 1);
  for (let length = longest; length >= 2; length--) {
    if (!isAsciiUpper(word[2 * length])) continue;
    const label = word.slice(0, length);
    if (word.startsWith(label, length)) return label;
  }
  return null;
}

/**
 * Undo glossary tooltips the crawler flattened into the text, e.g.
 * "a MoveMoveAn open source language for Sui. project" -> "a Move project".
 */
export function cleanTooltipText(text: string): string {
  // Zero-width spaces (&#8203;) come from the heading anchors.
  const input = text.replace(/\u200B/g, "");

  const words = /\w+/g;
  let cleaned = "";
  let consumed = 0;

  for (let word = words.exec(input); word; word = words.exec(input)) {
    const label = duplicatedLabel(word[0]);
    if (!label) continue;

    const period = input.indexOf(".", word.index + 2 * label.length);
    if (period === -1) continue;

    const resume = /\s/.test(input[period + 1] ?? "") ? period + 2 : period + 1;
    cleaned += input.slice(consumed, word.index) + label + " ";
    consumed = resume;
    words.lastIndex = resume;
  }

  return (cleaned + input.slice(consumed)).trim();
}

export type SnippetPart = { value: string; isHighlighted: boolean };

/**
 * Hit text is escaped twice: once in the index ("Coin&lt;T&gt;") and once by
 * InstantSearch. The decoded text is crawled, so render it only as React text.
 */
const toDisplayText = (value: string) => decode(decode(value));

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

function truncateParts(parts: SnippetPart[], maxChars: number): SnippetPart[] {
  const text = parts.map((part) => part.value).join("");
  if (text.length <= maxChars) return parts;

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

export function getSnippetParts(
  value: string,
  maxChars: number,
): SnippetPart[] {
  return truncateParts(parseHighlightedValue(value), maxChars);
}

/**
 * Hit URLs are crawled: only http(s) may reach an `href`, and a malformed URL
 * must not throw while rendering the result list.
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
