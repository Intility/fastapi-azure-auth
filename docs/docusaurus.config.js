const lightCodeTheme = require('prism-react-renderer/themes/github')
const darkCodeTheme = require('prism-react-renderer/themes/dracula')

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'FastAPI-Azure-Auth',
  tagline: 'Easy and secure implementation of Azure AD for your FastAPI APIs 🔒',
  url: 'https://your-docusaurus-test-site.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/global/favicon.ico',
  organizationName: 'Intility', // Usually your GitHub org/user name.
  projectName: 'FastAPI-Azure-Auth', // Usually your repo name.
  themeConfig: {
    navbar: {
      title: 'FastAPI-Azure-Auth',
      logo: {
        alt: 'FastAPI-Azure-Auth logo',
        src: 'img/global/fastad.png',
      },
      items: [
        {
          href: '/single-tenant',
          position: 'left',
          label: 'Single-tenant',
        },
        {
          href: '/multi-tenant',
          position: 'left',
          label: 'Multi-tenant',
        },
        {
          href: 'https://github.com/Intility/FastAPI-Azure-Auth',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Quick links',
          items: [
            {
              label: 'SECURITY.md',
              href: 'https://github.com/Intility/FastAPI-Azure-Auth/blob/main/SECURITY.md',
            },
            {
              label: 'jonas.svensson@intility.no',
              href: 'mailto:jonas.svensson@intility.no',
            },
            {
              label: 'Intility.com',
              href: 'https://intility.com',
            },
            {
              label: 'Azure',
              href: 'https://portal.azure.com',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Intility AS. Built with Docusaurus.`,
    },
    prism: {
      theme: lightCodeTheme,
      darkTheme: darkCodeTheme,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          id: 'single-tenant',
          path: 'single-tenant',
          routeBasePath: 'single-tenant',
          sidebarPath: require.resolve('./sidebarsSingleTenant.js'),
          editUrl: 'https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/',
          sidebarCollapsible: false,
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
  plugins: [
    require.resolve('docusaurus-lunr-search'),
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'multi-tenant',
        path: 'multi-tenant',
        routeBasePath: 'multi-tenant',
        sidebarPath: require.resolve('./sidebarsMultiTenant.js'),
        editUrl: 'https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/',
        sidebarCollapsible: false,
        // ... other options
      },
    ],
    // [
    //   '@docusaurus/plugin-content-docs',
    //   {
    //     id: 'single-tenants',
    //     path: 'single-tenant',
    //     routeBasePath: 'single-tenant',
    //     sidebarPath: require.resolve('./sidebarsSingleTenant.js'),
    //     editUrl: 'https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/',
    //     sidebarCollapsible: false,
    //     // ... other options
    //   },
    // ],
  ]
}
