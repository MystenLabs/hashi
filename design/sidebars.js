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
        'committee',
        'governance-actions',
        'sanctions',
        'service',
        'mpc-protocol',
        'guardian',
        'address-scheme',
        'limiter',
        'fees',
        'config',
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
