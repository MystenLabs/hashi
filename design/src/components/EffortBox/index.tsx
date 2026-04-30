// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Renders an "expected effort" admonition; driven by the `effort` frontmatter
// key (see src/shared/plugins/effort/index.js).

import React from "react";
import Admonition from "@theme/Admonition";

export default function EffortBox(props: { effort?: string }) {
  if (!props.effort) {
    return null;
  }

  function timeAndEffort(effort: string): [string, string] {
    if (effort[0] === "s") {
      return ["30-45 minutes", "basic"];
    } else if (effort[0] === "m") {
      return ["1-1.5 hours", "involved"];
    } else {
      return ["2 hours or more", "advanced"];
    }
  }

  const [time, effort] = timeAndEffort(props.effort);
  return (
    <Admonition
      type="info"
      title="Expected effort"
      icon="🧠"
      className="!my-12 bg-sui-ghost-white border-sui-ghost-dark dark:bg-sui-ghost-dark dark:border-sui-ghost-white"
    >
      <p className="pt-2">
        This guide is rated as <span className="font-bold">{effort}</span>.
      </p>
      <p>
        You can expect {effort} guides to take{" "}
        <span className="font-bold">{time}</span> of dedicated time. The length
        of time necessary to fully understand some of the concepts raised in
        this guide might increase this estimate.
      </p>
    </Admonition>
  );
}
