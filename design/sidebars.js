// @ts-check

// Sections:
//   Protocol     how Hashi works: flows, architecture, governance, security, fees
//   Integration  SDKs and integration guides
//   Validators   committee member runbooks
//   Reference    parameters and API links
// A planned hBTC section (deposit, withdraw, cancel, minimums and timing, FAQ)
// is omitted until it has pages.

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  designSidebar: [
    'README',
    {
      type: 'category',
      label: 'Protocol',
      collapsed: false,
      items: [
        'user-flows',
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
      label: 'Integration',
      collapsed: false,
      items: ['ts-sdk'],
    },
    {
      type: 'category',
      label: 'Validators',
      collapsed: false,
      items: ['node-operator-runbook', 'node-backup'],
    },
    {
      type: 'category',
      label: 'Reference',
      collapsed: false,
      items: [
        'config',
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
