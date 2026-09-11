// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { useHits } from "react-instantsearch";
import { useHistory } from "@docusaurus/router";
import HitSnippet from "./HitSnippet";
import {
  getDeepestHierarchyLabel,
  getHierarchyBreadcrumbs,
  cleanTooltipText,
  parseHitUrl,
} from "./utils";

const SNIPPET_MAX_CHARS = 250;

const linkStyle =
  "text-sm text-blue-700 dark:text-sui-blue-light hover:text-sui-blue-dark dark:hover:text-white font-medium underline";

/** Where to send someone whose search came up empty, per index. */
const elsewhere = new Map<string, React.ReactNode>([
  [
    "Hashi Docs",
    <>
      , or open an issue on{" "}
      <a
        href="https://github.com/MystenLabs/hashi/issues/new/choose"
        target="_blank"
        rel="noopener noreferrer"
      >
        GitHub
      </a>
      .
    </>,
  ],
  [
    "sui_docs",
    <>
      , or visit the official{" "}
      <a href="https://docs.sui.io" target="_blank" rel="noopener noreferrer">
        Sui Docs
      </a>{" "}
      site.
    </>,
  ],
  [
    "move_book",
    <>
      , or visit{" "}
      <a
        href="https://move-book.com/"
        target="_blank"
        rel="noopener noreferrer"
      >
        The Move Book
      </a>{" "}
      dedicated site.
    </>,
  ],
  [
    "sui_sdks",
    <>
      , or visit the official{" "}
      <a
        href="https://sdk.mystenlabs.com"
        target="_blank"
        rel="noopener noreferrer"
      >
        Sui SDKs
      </a>{" "}
      site.
    </>,
  ],
]);

export default function CustomHitsContent({ name }) {
  const { hits: items } = useHits();
  const history = useHistory();
  const currentHost = typeof window !== "undefined" ? window.location.host : "";

  if (items.length === 0) {
    return (
      <>
        <p>No results found.</p>
        <p>
          Try your search again with different keywords
          {elsewhere.get(name) ?? "."}
        </p>
      </>
    );
  }

  // Keyed by a crawled field, so a Map rather than an object literal.
  const grouped = new Map<string, typeof items>();
  for (const hit of items) {
    const group = grouped.get(hit.url_without_anchor);
    if (group) group.push(hit);
    else grouped.set(hit.url_without_anchor, [hit]);
  }

  return (
    <>
      {Array.from(grouped.values()).map((group, index) => {
        const pageCrumbs = getHierarchyBreadcrumbs(group[0].hierarchy);
        const pageTitle =
          pageCrumbs.length > 0
            ? pageCrumbs[Math.min(1, pageCrumbs.length - 1)]
            : "[no title]";

        return (
          <div
            className="p-6 pb-6 mb-6 bg-sui-gray-35 dark:bg-sui-gray-85 rounded-2xl"
            key={index}
          >
            <div className="text-lg font-semibold mb-1 text-gray-900 dark:text-white">
              {pageTitle}
            </div>
            {pageCrumbs.length > 0 && (
              <div className="text-xs text-gray-500 dark:text-sui-gray-50 mb-4">
                {pageCrumbs.join(" > ")}
              </div>
            )}
            <div className="space-y-3">
              {group.map((hit, i) => {
                const hitCrumbs = getHierarchyBreadcrumbs(hit.hierarchy);
                const sectionTitle =
                  hitCrumbs.length > 0
                    ? hitCrumbs[hitCrumbs.length - 1]
                    : cleanTooltipText(getDeepestHierarchyLabel(hit.hierarchy));

                const target = parseHitUrl(hit.url);
                const internalPath =
                  target && target.host === currentHost
                    ? target.pathname
                    : null;

                return (
                  <div key={i} className="py-1">
                    {internalPath ? (
                      <button
                        onClick={() => history.push(internalPath)}
                        className={`${linkStyle} text-left bg-transparent border-0 pl-0 cursor-pointer`}
                      >
                        {sectionTitle}
                      </button>
                    ) : (
                      <a
                        href={target?.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={linkStyle}
                      >
                        {sectionTitle}
                      </a>
                    )}
                    {hit._highlightResult?.content?.value && (
                      <HitSnippet
                        value={hit._highlightResult.content.value}
                        maxChars={SNIPPET_MAX_CHARS}
                        className="font-normal text-sm text-gray-600 dark:text-sui-gray-45 mt-1"
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </>
  );
}
