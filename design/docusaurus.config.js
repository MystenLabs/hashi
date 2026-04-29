// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'hashi',
  tagline: 'Sui native Bitcoin orchestrator',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://mystenlabs.github.io',
  baseUrl: '/hashi/design/',

  organizationName: 'MystenLabs',
  projectName: 'hashi',

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    format: 'detect',
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: ['@docusaurus/theme-mermaid'],

  plugins: [
    'docusaurus-plugin-copy-page-button',
    [
      '@docusaurus/plugin-client-redirects',
      {
        // mdbook served pages at `<slug>.html`; redirect those to the
        // clean Docusaurus URLs so old links continue to work.
        createRedirects(existingPath) {
          // Skip the docs root (GitHub Pages already serves index.html there)
          // and any path that already ends in `.html` (e.g. /404.html).
          if (existingPath === '/' || existingPath.endsWith('.html')) {
            return undefined;
          }
          return [`${existingPath}.html`];
        },
      },
    ],
  ],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: 'docs',
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/MystenLabs/hashi/edit/main/design/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Hashi',
        logo: {
          alt: 'Hashi logo',
          src: 'img/logo.svg',
          srcDark: 'img/logo-dark.svg',
          href: '/',
        },
        items: [
          {
            href: 'https://github.com/MystenLabs/hashi',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['rust', 'toml', 'bash'],
      },
    }),
};

export default config;
