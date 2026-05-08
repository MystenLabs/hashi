// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Fetches a file from a remote URL and renders it as a syntax-highlighted code
// block, optionally slicing by line range and prepending/appending text.

import React, { useEffect, useState } from "react";
import { Highlight, themes, Prism, Language } from "prism-react-renderer";
import CopyButton from "@theme/CodeBlock/Buttons/CopyButton";

import styles from "./styles.module.css";
require("prismjs/components/prism-rust");

type LangExt = Language | "rust";

const BASE = "https://raw.githubusercontent.com/MystenLabs/hashi/main";

export default function ExampleImport(props: {
  file: string;
  type?: string;
  lineStart?: number;
  lineEnd?: number;
  showLineNumbers?: boolean;
  appendToCode?: string;
  prependToCode?: string;
}) {
  const [example, setExample] = useState<string | null>(null);
  const {
    file,
    type,
    lineStart,
    lineEnd,
    showLineNumbers,
    appendToCode,
    prependToCode,
  } = props;
  const fileUrl = BASE + file;
  const fileExt = file.split(".").pop() ?? "";
  const prefix = file.replaceAll("/", "_").replaceAll(".", "_").toLowerCase();
  const subStart = (lineStart ?? 1) - 1 || 0;
  const subEnd = lineEnd || 0;

  let highlight: LangExt = fileExt as LangExt;
  if (type === "move" || highlight === "move") {
    highlight = "rust";
  } else if (typeof type !== "undefined") {
    highlight = type as LangExt;
  }

  useEffect(() => {
    let cancelled = false;
    fetch(fileUrl)
      .then((r) => r.text())
      .then((text) => {
        if (cancelled) return;
        if (subStart > 0 || subEnd > 0) {
          let lines = text.split("\n");
          if (subStart > 0 && subEnd > 0) {
            lines.splice(0, subStart);
            lines.splice(subEnd - subStart, lines.length);
          } else if (subStart > 0) {
            lines.splice(0, subStart);
          } else if (subEnd > 0) {
            lines.splice(subEnd, lines.length);
          }
          if (appendToCode) lines = [...lines, ...appendToCode.split("\n")];
          if (prependToCode) lines = [...prependToCode.split("\n"), ...lines];
          setExample(lines.join("\n"));
        } else {
          setExample(text);
        }
      })
      .catch(() => {
        if (!cancelled) setExample("Error loading file.");
      });
    return () => {
      cancelled = true;
    };
  }, [fileUrl, subStart, subEnd, appendToCode, prependToCode]);

  if (!example) return null;

  return (
    <Highlight
      Prism={Prism}
      code={example}
      language={highlight as Language}
      theme={themes.github}
    >
      {({ tokens, getLineProps, getTokenProps }) => (
        <div className="theme-code-block">
          <div>
            <pre>
              {tokens.map((line, i) => (
                <div key={"div_" + prefix + i} {...getLineProps({ line })}>
                  {showLineNumbers && (
                    <span className={styles.lineNumbers}>
                      {i + 1}
                      {"\t"}
                    </span>
                  )}
                  {line.map((token, key) => (
                    <span key={prefix + key} {...getTokenProps({ token })} />
                  ))}
                </div>
              ))}
            </pre>
            <div>
              <CopyButton code={example} />
            </div>
          </div>
        </div>
      )}
    </Highlight>
  );
}
