// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { getSnippetParts } from "./utils";

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
