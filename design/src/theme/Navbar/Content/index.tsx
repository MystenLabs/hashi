// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Swizzled navbar content (wrap mode). Renders Docusaurus's default
// NavbarContent then appends our custom SearchLauncher button into the
// right-side flex container via a portal. The launcher opens the
// react-instantsearch modal at src/components/Search/SearchModal.tsx.

import React from "react";
import OriginalNavbarContent from "@theme-original/Navbar/Content";
import { createPortal } from "react-dom";
import ExecutionEnvironment from "@docusaurus/ExecutionEnvironment";
import SearchModal from "@site/src/components/Search/SearchModal";

function SearchLauncher() {
  const [open, setOpen] = React.useState(false);

  // Cmd-K / Ctrl-K opens the modal.
  React.useEffect(() => {
    if (!ExecutionEnvironment.canUseDOM) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      <button
        type="button"
        className="search-launcher-btn"
        onClick={() => setOpen(true)}
        aria-label="Search"
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 20 20"
          aria-hidden="true"
          className="search-launcher-btn__icon"
        >
          <path
            d="M14.386 14.386l4.0877 4.0877-4.0877-4.0877c-2.9418 2.9419-7.7115 2.9419-10.6533 0-2.9419-2.9418-2.9419-7.7115 0-10.6533 2.9418-2.9419 7.7115-2.9419 10.6533 0 2.9419 2.9418 2.9419 7.7115 0 10.6533z"
            stroke="currentColor"
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="2"
          />
        </svg>
        <span className="search-launcher-btn__label">Search</span>
        <span className="search-launcher-btn__kbd">
          <kbd>⌘</kbd>
          <kbd>K</kbd>
        </span>
      </button>
      <SearchModal isOpen={open} onClose={() => setOpen(false)} />
    </>
  );
}

export default function NavbarContentWrapper(props: any) {
  const [container, setContainer] = React.useState<HTMLElement | null>(null);

  // After the original navbar renders, find its right-side container and
  // mount the launcher in front of the existing items (GitHub link, kapa
  // button). This keeps Docusaurus's responsive collapse working — items
  // already in the right-side container get collapsed by the theme on
  // narrow screens, and our launcher tags along.
  React.useEffect(() => {
    if (!ExecutionEnvironment.canUseDOM) return;
    const find = () => {
      const right = document.querySelector(".navbar__items--right");
      if (right && right !== container) setContainer(right as HTMLElement);
    };
    find();
    // The right container can re-render across route changes — observe.
    const obs = new MutationObserver(find);
    obs.observe(document.body, { childList: true, subtree: true });
    return () => obs.disconnect();
  }, [container]);

  return (
    <>
      <OriginalNavbarContent {...props} />
      {container ? createPortal(<SearchLauncher />, container) : null}
    </>
  );
}
