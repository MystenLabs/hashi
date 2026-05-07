// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Client module — fires a Plausible pageview on every SPA route change with
// a `visitor_type` custom prop ("human" | "agent" | "bot") derived from the
// user agent string. Mirrors detection logic from
// https://github.com/MystenLabs/seal/pull/546:
//   - `agent`: an AI tool (Claude Code, Cursor, ChatGPT, etc.)
//   - `bot`:   a traditional crawler/scraper (Googlebot, headless Chrome,
//              Selenium/Puppeteer/Playwright, generic spiders)
//   - `human`: everyone else
// Server-side detection for AI agents that never run JS (curl-style fetches)
// lives in middleware.js at the docs root.

import ExecutionEnvironment from "@docusaurus/ExecutionEnvironment";

const AI_AGENT_PATTERNS =
  /claude[-_]?code|anthropic|cursor|copilot|chatgpt|openai|gptbot|perplexity|cohere|codeium|windsurf|tabnine|sourcegraph|cody/i;
const BOT_PATTERNS =
  /bot|crawler|spider|crawling|headless|puppet|phantom|selenium|playwright|archiver|fetcher|slurp|mediapartners/i;

function detectVisitorType() {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  if (AI_AGENT_PATTERNS.test(ua)) return "agent";
  if (BOT_PATTERNS.test(ua)) return "bot";
  if (typeof navigator !== "undefined" && navigator.webdriver) return "bot";
  return "human";
}

export async function onRouteDidUpdate({ location }) {
  if (!ExecutionEnvironment.canUseDOM) return;

  const opts = window.__PLAUSIBLE_OPTS__ || {};
  const isProd = process.env.NODE_ENV === "production";
  if (!isProd && !opts.enableInDev) return;
  if (!opts.domain) return;

  const mod = await import("@plausible-analytics/tracker");
  const init = typeof mod.default === "function" ? mod.default : mod.init;

  if (!window.__plausible_inited__) {
    if (typeof init !== "function") {
      console.error(
        "[plausible] init is not a function; module exports:",
        Object.keys(mod),
      );
      return;
    }
    try {
      const instance = init({
        domain: opts.domain,
        apiHost: opts.apiHost,
        hashMode: !!opts.hashMode,
        trackLocalhost: !!opts.trackLocalhost,
      });
      if (instance) {
        window.__plausible_instance__ = instance;
      }
      window.__plausible_inited__ = true;
    } catch (e) {
      console.error("[plausible] init threw", e);
      return;
    }
  }

  const track = window.__plausible_instance__?.track || mod.track;

  if (typeof track !== "function") {
    console.error(
      "[plausible] track is not a function; instance/mod were:",
      window.__plausible_instance__,
      Object.keys(mod),
    );
    return;
  }

  track("pageview", {
    url: location.pathname + location.search + location.hash,
    referrer: document.referrer || undefined,
    props: {
      visitor_type: detectVisitorType(),
    },
  });
}
