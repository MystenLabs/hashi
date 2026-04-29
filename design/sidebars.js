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
        {type: 'doc', id: 'sanctions', label: 'Handling Sanctions'},
        'service',
        'mpc-protocol',
        'guardian',
        {type: 'doc', id: 'address-scheme', label: 'Address Scheme'},
        {type: 'doc', id: 'limiter', label: 'Limiter'},
        'fees',
        {type: 'doc', id: 'config', label: 'Configuration'},
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
  ],
};

export default sidebars;
