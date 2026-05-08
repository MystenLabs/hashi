// @ts-check
// See: https://docusaurus.io/docs/api/docusaurus-config

import { themes as prismThemes } from 'prism-react-renderer';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const betaRemarkPlugin = require('./src/shared/plugins/betatag');
const effortRemarkPlugin = require('./src/shared/plugins/effort');
// remark-glossary uses ESM `export default`; pull the actual function out.
const remarkGlossary =
  require('./src/shared/plugins/remark-glossary.js').default ||
  require('./src/shared/plugins/remark-glossary.js');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Hashi',
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
    format: 'mdx',
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: ['@docusaurus/theme-mermaid'],

  scripts: [
    {
      src: 'https://widget.kapa.ai/kapa-widget.bundle.js',
      'data-website-id': '8bd95839-754a-4bef-8ea5-4e0a0617227a',
      'data-project-name': 'Hashi Knowledge',
      'data-project-color': '#298DFF',
      // The default kapa floating button is hidden — the trigger lives in the
      // navbar (top-right), wired up below as an `html` navbar item.
      'data-button-hide': 'true',
      'data-modal-title': 'Ask Hashi AI',
      'data-modal-ask-ai-input-placeholder': 'Ask me anything about Hashi!',
      'data-modal-example-questions':
        'How does the deposit flow work?,What does the Guardian do?,How does Hashi handle Bitcoin reorganizations?,What are the MPC committee thresholds?',
      'data-modal-image': '/hashi/design/img/logo.svg',
      async: true,
    },
  ],

  plugins: [
    // Inject <link rel="alternate" type="text/plain" href="/llms.txt"> into
    // every page so agents following the agentdocsspec.com convention can
    // discover the LLM-optimized index.
    function llmsTxtDirectivePlugin() {
      return {
        name: 'llms-txt-directive-plugin',
        injectHtmlTags() {
          return {
            preBodyTags: [
              {
                tagName: 'link',
                attributes: {
                  rel: 'alternate',
                  type: 'text/plain',
                  href: '/hashi/design/llms.txt',
                  title: 'LLMs.txt',
                },
              },
            ],
          };
        },
      };
    },
    // Serve `Content-Type: text/markdown` for `.md` URLs in dev (`npm run start`)
    // so content-negotiation works locally. On GitHub Pages, `.md` files are
    // already served with `text/markdown; charset=UTF-8` because we ship a
    // `.nojekyll` and the content-type is mapped from the file extension.
    function markdownHeadersPlugin() {
      return {
        name: 'markdown-headers-plugin',
        configureWebpack() {
          return {
            devServer: {
              setupMiddlewares(middlewares) {
                middlewares.unshift({
                  name: 'markdown-content-type',
                  middleware: (req, res, next) => {
                    if (req.url.endsWith('.md')) {
                      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
                      res.setHeader('Content-Disposition', 'inline');
                    } else if (req.url.endsWith('.txt')) {
                      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                      res.setHeader('Content-Disposition', 'inline');
                    }
                    next();
                  },
                });
                return middlewares;
              },
            },
          };
        },
      };
    },
    'docusaurus-plugin-copy-page-button',
    [
      '@docusaurus/plugin-client-redirects',
      {
        createRedirects(existingPath) {
          if (existingPath === '/' || existingPath.endsWith('.html')) {
            return undefined;
          }
          return [`${existingPath}.html`];
        },
      },
    ],
    // Sui-style toolkit
    require.resolve('./src/shared/plugins/inject-code'),
    require.resolve('./src/shared/plugins/descriptions'),
    [
      require.resolve('./src/shared/plugins/plausible'),
      {
        domain: 'mystenlabs.github.io/hashi/design',
        enableInDev: false,
        trackOutboundLinks: true,
        hashMode: false,
        trackLocalhost: false,
      },
    ],
    // Tailwind via PostCSS
    function tailwindPlugin() {
      return {
        name: 'hashi-tailwind',
        configurePostCss(postcssOptions) {
          postcssOptions.plugins.push(require('tailwindcss'));
          postcssOptions.plugins.push(require('autoprefixer'));
          return postcssOptions;
        },
      };
    },
    // Webpack aliases used by Sui-style components (@docs, @generated-imports)
    function aliasPlugin() {
      return {
        name: 'hashi-webpack-aliases',
        configureWebpack() {
          return {
            resolve: {
              alias: {
                '@docs': path.resolve(__dirname, 'docs'),
                '@generated-imports': path.resolve(__dirname, '.generated'),
                '@repo': path.resolve(__dirname, '..'),
              },
            },
          };
        },
      };
    },
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
          exclude: ['**/snippets/**'],
          admonitions: {
            keywords: ['checkpoint'],
            extendDefaults: true,
          },
          remarkPlugins: [
            effortRemarkPlugin,
            betaRemarkPlugin,
            [
              remarkGlossary,
              {
                glossaryFile: path.resolve(__dirname, 'static/glossary.json'),
              },
            ],
          ],
        },
        blog: false,
        theme: {
          customCss: [require.resolve('./src/css/custom.css')],
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
            type: 'html',
            position: 'right',
            value:
              '<button type="button" class="kapa-trigger-btn" onclick="window.Kapa && window.Kapa.open()" aria-label="Ask Hashi AI">' +
              '<img src="/hashi/design/img/logo.svg" alt="" width="20" height="20" />' +
              '<span class="kapa-trigger-btn__label">Ask Hashi AI</span>' +
              '</button>',
          },
          {
            href: 'https://github.com/MystenLabs/hashi',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      // Mermaid diagrams follow the Sui Technical Diagram Standards:
      // https://docs.sui.io/references/contribute/diagram-standards
      // Per-diagram frontmatter is reserved for diagram-specific things
      // (titles, layout knobs) — never for color overrides.
      mermaid: {
        theme: { light: 'base', dark: 'base' },
        options: {
          themeVariables: {
            primaryColor: '#000000',
            primaryTextColor: '#FFFFFF',
            primaryBorderColor: '#6C7584',
            secondaryColor: '#6C7584',
            secondaryTextColor: '#FFFFFF',
            tertiaryColor: '#298DFF',
            tertiaryTextColor: '#FFFFFF',
            lineColor: '#298DFF',
            background: '#FFFFFF',
            mainBkg: '#000000',
            secondBkg: '#6C7584',
            noteBkgColor: '#E6F1FB',
            noteTextColor: '#000000',
            noteBorderColor: '#298DFF',
            activationBkgColor: '#298DFF',
            activationBorderColor: '#185FA5',
            fontSize: '14px',
            fontFamily: 'Inter, sans-serif',
            signalColor: '#298DFF',
            signalTextColor: '#298DFF',
            labelBoxBkgColor: '#000000',
            labelBoxBorderColor: '#6C7584',
            labelTextColor: '#FFFFFF',
            loopTextColor: '#FFFFFF',
          },
        },
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['rust', 'toml', 'bash'],
      },
    }),
};

export default config;
