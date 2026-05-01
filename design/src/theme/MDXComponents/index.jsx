// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Globally registers our shared component toolkit so MDX pages can use
// <Tabs>, <UnsafeLink>, <BetaTag>, <ImportContent>, etc. without per-file
// import statements.

import React from "react";
import MDXComponentsOriginal from "@theme-original/MDXComponents";
import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";
import CodeBlock from "@theme/CodeBlock";
import DocCardList from "@theme/DocCardList";
import BrowserOnly from "@docusaurus/BrowserOnly";
import { Card, Cards } from "@site/src/shared/components/Cards";
import UnsafeLink from "@site/src/shared/components/UnsafeLink";
import RelatedLink from "@site/src/shared/components/RelatedLink";
import ImportContent from "@site/src/shared/components/ImportContent";
import Snippet from "@site/src/shared/components/Snippet";
import ExampleImport from "@site/src/shared/components/ExampleImport";
import SidebarIframe from "@site/src/shared/components/SidebarIframe";
import ThemeToggle from "@site/src/shared/components/ThemeToggle";
import Term from "@site/src/shared/components/Glossary/Term";
import BetaTag from "@site/src/components/BetaTag";
import EffortBox from "@site/src/components/EffortBox";

export default {
  ...MDXComponentsOriginal,
  Card,
  Cards,
  Tabs,
  TabItem,
  CodeBlock,
  DocCardList,
  BrowserOnly,
  UnsafeLink,
  RelatedLink,
  ImportContent,
  Snippet,
  ExampleImport,
  SidebarIframe,
  ThemeToggle,
  Term,
  BetaTag,
  EffortBox,
};
