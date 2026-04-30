// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Injects an <EffortBox effort="..." /> MDX node at the top of any page that
// declares `effort:` (small/medium/large) in its frontmatter.

function effortRemarkPlugin() {
  return (tree, file) => {
    if (file.data.frontMatter && file.data.frontMatter.effort) {
      const effortValue = file.data.frontMatter.effort;
      const customComponentNode = {
        type: "mdxJsxFlowElement",
        name: "EffortBox",
        attributes: [
          {
            type: "mdxJsxAttribute",
            name: "effort",
            value: effortValue,
          },
        ],
        children: [],
      };
      tree.children.unshift(customComponentNode);
    }
  };
}

module.exports = effortRemarkPlugin;
