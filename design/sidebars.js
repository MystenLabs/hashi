// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  designSidebar: [
    'README',
    'user-flows',
    {
      type: 'category',
      label: 'Design',
      collapsed: true,
      items: [
        {
          type: 'category',
          label: 'Architecture',
          collapsed: false,
          items: ['service', 'committee', 'mpc-protocol', 'guardian'],
        },
        {
          type: 'category',
          label: 'Bitcoin handling',
          collapsed: false,
          items: ['address-scheme', 'fees', 'limiter', 'sanctions'],
        },
        {
          type: 'category',
          label: 'Governance',
          collapsed: false,
          items: ['config', 'governance-actions', 'move-upgrades'],
        },
      ],
    },
    {
      type: 'category',
      label: 'Flows',
      collapsed: true,
      items: [
        'reconfiguration',
        'deposit',
        'withdraw',
        'move-model-lifecycle',
      ],
    },
    {
      type: 'category',
      label: 'Operators',
      collapsed: true,
      items: [
        'node-operator-runbook',
        'node-backup',
      ],
    },
    {
      type: 'category',
      label: 'SDKs',
      collapsed: true,
      items: [
        'ts-sdk',
      ],
    },
  ],
};

export default sidebars;
