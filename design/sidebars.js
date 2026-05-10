// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  designSidebar: [
    'README',
    'user-flows',
    {
      type: 'category',
      label: 'Design',
      collapsed: false,
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
      collapsed: false,
      items: [
        'reconfiguration',
        'deposit',
        'withdraw',
      ],
    },
    {
      type: 'category',
      label: 'Ecosystem',
      collapsed: false,
      items: [
        'ecosystem/epoch-vesting',
      ],
    },
  ],
};

export default sidebars;
