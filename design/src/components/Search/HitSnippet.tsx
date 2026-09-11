// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { getSnippetParts } from "./utils";

/**
 * The excerpt shown under a search hit, with the query matches marked.
 *
 * The excerpt is crawled content, so it is rendered as React children: the
 * browser never parses it as HTML. This is the whole reason the component
 * exists instead of a string handed to `dangerouslySetInnerHTML`.
 */
export default function HitSnippet({
  value,
  maxChars,
  className,
}: {
  value: string;
  maxChars: number;
  className?: string;
}) {
  return (
    <p className={className}>
      {getSnippetParts(value, maxChars).map((part, index) =>
        part.isHighlighted ? (
          <mark key={index}>{part.value}</mark>
        ) : (
          <React.Fragment key={index}>{part.value}</React.Fragment>
        ),
      )}
    </p>
  );
}
