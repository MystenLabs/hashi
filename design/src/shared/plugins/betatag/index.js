// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Injects a <BetaTag beta="..." /> MDX node at the top of any page that
// declares `beta:` in its frontmatter.

function betaRemarkPlugin() {
  return (tree, file) => {
    if (file.data.frontMatter && file.data.frontMatter.beta) {
      const betaValue = file.data.frontMatter.beta;
      const customComponentNode = {
        type: "mdxJsxFlowElement",
        name: "BetaTag",
        attributes: [
          {
            type: "mdxJsxAttribute",
            name: "beta",
            value: betaValue,
          },
        ],
        children: [],
      };
      tree.children.unshift(customComponentNode);
    }
  };
}

module.exports = betaRemarkPlugin;
