/*
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
*/

/**
 * OpenInPlayMoveButton — shared button that opens the nearest code block in
 * PlayMove (https://www.playmove.dev) in a new tab. Designed to sit inside a
 * Docusaurus CodeBlock button bar, alongside Copy and OpenInAgentButton.
 *
 * PlayMove reads its initial editor contents from the URL hash, so we open
 * `https://www.playmove.dev/#<encodeURIComponent(code)>`.
 *
 * The button only appears on Move code blocks: it walks the DOM upward from its
 * own position to find a `pre code[class*='language-move']` element, and stays
 * hidden otherwise. The wrapper span always renders so the ref is available on
 * mount; we toggle its display once detection has run.
 */
import React, {
  useState,
  useRef,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import clsx from "clsx";
import styles from "./styles.module.css";

const PLAYMOVE_URL = "https://www.playmove.dev";

/** Walk up from `start` to find the nearest code text in the code block. */
function getNearestCodeText(start: HTMLElement | null): string {
  let el: HTMLElement | null = start;
  while (el) {
    const code = el.querySelector?.(
      "pre code, code, pre",
    ) as HTMLElement | null;
    if (code?.innerText) {
      return code.innerText.replace(/\n$/, "");
    }
    el = el.parentElement;
  }
  return "";
}

export default function OpenInPlayMoveButton({
  className,
  ButtonComponent,
}: {
  className?: string;
  /** Optional base button component from the site's theme (e.g. @theme/CodeBlock/Buttons/Button).
   *  Falls back to a plain <button> when not provided. */
  ButtonComponent?: React.ComponentType<
    React.ButtonHTMLAttributes<HTMLButtonElement>
  >;
}): ReactNode {
  const wrapperRef = useRef<HTMLSpanElement | null>(null);
  const [isMove, setIsMove] = useState(false);

  const Btn = ButtonComponent ?? "button";

  // Detect whether the surrounding code block is Move. Docusaurus puts the
  // `language-move` class on the <pre> (not the <code>), so match the <pre>.
  useEffect(() => {
    let el: HTMLElement | null = wrapperRef.current;
    while (el) {
      if (el.querySelector?.("pre[class*='language-move']")) {
        setIsMove(true);
        return;
      }
      el = el.parentElement;
    }
  }, []);

  const handleClick = useCallback(() => {
    const code = getNearestCodeText(wrapperRef.current);
    if (!code) return;
    window.open(
      `${PLAYMOVE_URL}/#${encodeURIComponent(code)}`,
      "_blank",
      "noopener",
    );
  }, []);

  return (
    <span
      ref={wrapperRef}
      className={styles.wrapper}
      style={{ display: isMove ? "inline-flex" : "none" }}
    >
      <Btn
        type="button"
        className={clsx(className, styles.triggerBtn, "clean-btn")}
        aria-label="Open in Move Playground"
        title="Open in Move Playground"
        onClick={handleClick}
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M8 5v14l11-7z" />
        </svg>
        <span className={styles.label}>Playground</span>
      </Btn>
    </span>
  );
}
