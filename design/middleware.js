// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Server-side Plausible event tracking for AI agents that never run
// client-side JS. Mirrors the middleware added in
// https://github.com/MystenLabs/seal/pull/546.
//
// This file follows the Vercel/Cloudflare/edge-middleware export shape
// (`export const config = { matcher: [...] }` + default async function).
// GitHub Pages does NOT run middleware, so this is dormant on the current
// gh-pages deployment but ready to ship as-is on any Vercel/Walrus-on-edge
// deploy without modification.

const AI_AGENT_PATTERN =
  /claude[-_]?code|anthropic|cursor|copilot|chatgpt|openai|gptbot|perplexity|cohere|codeium|windsurf|tabnine|sourcegraph|cody/i;

function detectServerVisitorType(request) {
  const ua = request.headers.get('user-agent') || '';
  const accept = request.headers.get('accept') || '';
  if (AI_AGENT_PATTERN.test(ua)) return 'agent';
  if (accept.includes('text/markdown')) return 'agent';
  return null;
}

function trackPlausibleEvent(request, visitorType) {
  const url = new URL(request.url);
  const ua = request.headers.get('user-agent') || '';
  const ip =
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    '';

  fetch('https://plausible.io/api/event', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': ua,
      'X-Forwarded-For': ip,
    },
    body: JSON.stringify({
      name: 'pageview',
      domain: 'mystenlabs.github.io/hashi/design',
      url: url.toString(),
      referrer: request.headers.get('referer') || '',
      props: { visitor_type: visitorType },
    }),
  }).catch(() => {});
}

export const config = {
  matcher: [
    '/((?!_next|api|static|img|fonts|favicon).*)',
  ],
};

export default async function middleware(request) {
  const visitorType = detectServerVisitorType(request);
  if (visitorType === 'agent') {
    trackPlausibleEvent(request, visitorType);
  }
  return;
}
