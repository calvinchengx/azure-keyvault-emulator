import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// Project GitHub Pages site: https://calvinchengx.github.io/azure-keyvault-emulator/
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/azure-keyvault-emulator/',
  // remarkMermaid turns ```mermaid fences into <pre class="mermaid"> before
  // Expressive Code sees them; src/components/Head.astro renders them client-side.
  markdown: {
    remarkPlugins: [remarkMermaid],
  },
  integrations: [
    starlight({
      title: 'Azure Key Vault Emulator',
      components: {
        Head: './src/components/Head.astro',
      },
      description:
        'A local emulator of the Azure Key Vault data plane — secrets, keys, and certificates — with real challenge-based authentication against entra-emulator.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/calvinchengx/azure-keyvault-emulator' },
      ],
      editLink: {
        baseUrl: 'https://github.com/calvinchengx/azure-keyvault-emulator/edit/main/docs/',
      },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { slug: 'index' },
            { slug: '01-quickstart' },
            { slug: '02-installation' },
            { slug: '03-architecture' },
            { slug: '04-configuration' },
            { slug: '05-tls-and-vaults' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: '06-secrets' },
            { slug: '07-keys' },
            { slug: '08-certificates' },
            { slug: '09-authentication' },
          ],
        },
        {
          label: 'Testing',
          items: [
            { slug: '10-testing' },
            { slug: '11-family-integration' },
          ],
        },
        {
          label: 'Project',
          items: [
            { slug: '12-roadmap' },
            { slug: '13-entra-companion' },
          ],
        },
      ],
    }),
  ],
});
