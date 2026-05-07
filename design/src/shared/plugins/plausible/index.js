// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// In-repo Plausible plugin for Docusaurus 3.x. Uses manual tracking via
// @plausible-analytics/tracker so we can attach custom props (notably
// visitor_type: human | agent) to every pageview event.

const path = require("path");

/**
 * @typedef {Object} PlausibleOptions
 * @property {string} domain - bare hostname, e.g. "hashi-docs.mystenlabs.com"
 * @property {string} [apiHost] - optional, e.g. "https://plausible.io"
 * @property {boolean} [enableInDev] - allow tracking when not production
 * @property {boolean} [trackOutboundLinks] - default true
 * @property {boolean} [hashMode] - track hash-based routing
 * @property {boolean} [trackLocalhost] - default false
 */

/**
 * @param {import('@docusaurus/types').LoadContext} _context
 * @param {PlausibleOptions} options
 * @returns {import('@docusaurus/types').Plugin}
 */
function pluginPlausible(_context, options) {
  const injectJson = JSON.stringify({
    ...options,
    trackOutboundLinks: options.trackOutboundLinks ?? true,
    trackLocalhost: options.trackLocalhost ?? false,
  });

  return {
    name: "hashi-plugin-plausible",

    injectHtmlTags() {
      return {
        preBodyTags: [
          {
            tagName: "script",
            attributes: { type: "text/javascript" },
            innerHTML: `window.__PLAUSIBLE_OPTS__ = ${injectJson};`,
          },
        ],
      };
    },

    getClientModules() {
      return [path.resolve(__dirname, "./client")];
    },
  };
}

module.exports = pluginPlausible;
