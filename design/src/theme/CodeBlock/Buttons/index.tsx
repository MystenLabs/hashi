// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Swizzled (ejected) CodeBlock button bar. Renders the stock WordWrap + Copy
// buttons, then our shared "Use an Agent" and "Playground" buttons. The
// Playground button only appears on Move code blocks (it self-hides otherwise).
//
// Based on the upstream @docusaurus/theme-classic CodeBlock/Buttons component.

import React, { type ReactNode } from "react";
import clsx from "clsx";
import BrowserOnly from "@docusaurus/BrowserOnly";
import CopyButton from "@theme/CodeBlock/Buttons/CopyButton";
import WordWrapButton from "@theme/CodeBlock/Buttons/WordWrapButton";
import Button from "@theme/CodeBlock/Buttons/Button";
import OpenInAgentButton from "@site/src/shared/components/OpenInAgentButton";
import OpenInPlayMoveButton from "@site/src/shared/components/OpenInPlayMoveButton";
import styles from "./styles.module.css";

interface Props {
  className?: string;
}

// Code block buttons are not server-rendered on purpose: adding them to the
// initial HTML is useless and expensive (JSX SVG). They become interactive once
// React hydrates.
export default function CodeBlockButtons({ className }: Props): ReactNode {
  return (
    <BrowserOnly>
      {() => (
        <div className={clsx(className, styles.buttonGroup)}>
          <WordWrapButton />
          <CopyButton />
          <OpenInAgentButton ButtonComponent={Button} />
          <OpenInPlayMoveButton ButtonComponent={Button} />
        </div>
      )}
    </BrowserOnly>
  );
}
