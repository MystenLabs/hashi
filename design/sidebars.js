// @ts-check

// Sections:
//   Protocol     how Hashi works: architecture, lifecycles, governance, security, fees
//   hBTC         user flows overview, deposit, withdraw, cancel, FAQ
//   Integration  SDKs and integration guides
//   Validators   committee member runbooks
//   Reference    parameters and API links

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  designSidebar: [
    'README',
    {
      type: 'category',
      label: 'Protocol',
      collapsed: true,
      items: [
        {
          type: 'category',
          label: 'Architecture',
          collapsed: true,
          items: [
            'service',
            'committee',
            'mpc-protocol',
            'guardian',
            'address-scheme',
            'move-model-lifecycle',
          ],
        },
        'deposit',
        'withdraw',
        'reconfiguration',
        {
          type: 'category',
          label: 'Governance',
          collapsed: true,
          items: ['governance-actions', 'move-upgrades'],
        },
        {
          type: 'category',
          label: 'Security',
          collapsed: true,
          items: ['limiter', 'sanctions'],
        },
        'fees',
      ],
    },
    {
      type: 'category',
      label: 'hBTC',
      collapsed: true,
      items: [
        'user-flows',
        'hbtc/deposit',
        'hbtc/withdraw',
        'hbtc/cancel',
        'hbtc/faq',
      ],
    },
    {
      type: 'category',
      label: 'Integration',
      collapsed: true,
      items: ['ts-sdk'],
    },
    {
      type: 'category',
      label: 'Validators',
      collapsed: true,
      link: { type: 'doc', id: 'validators/index' },
      items: [
        'validators/prerequisites',
        'validators/keys',
        'validators/configuration',
        'validators/genesis',
        'validators/governance',
        'validators/monitoring',
        'validators/epoch-changes',
        'validators/backup-restore',
        'node-backup',
        'validators/troubleshooting',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      collapsed: true,
      items: [
        'reference/networks',
        'config',
        'reference/cli',
        'reference/releases',
        {
          type: 'link',
          label: 'Move Package',
          href: 'https://github.com/MystenLabs/hashi/tree/main/packages/hashi',
        },
        {
          type: 'link',
          label: 'gRPC API',
          href: 'https://github.com/MystenLabs/hashi/tree/main/crates/hashi-types/proto/sui/hashi/v1alpha',
        },
        {
          type: 'link',
          label: 'Rust API',
          href: 'https://mystenlabs.github.io/hashi/rustdoc/hashi',
        },
      ],
    },
  ],
};

export default sidebars;
