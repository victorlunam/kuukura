// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { REPO_URL, SIDEBAR, SITE } from './site.config.mjs';

const link = (/** @type {{ slug: string }} */ p) => `/docs/${p.slug ? `${p.slug}/` : ''}`;
const sidebar = SIDEBAR.map((s) => {
  const only = s.pages.length === 1 ? s.pages[0] : undefined;
  return only && only.label === s.label
    ? { label: s.label, link: link(only) }
    : { label: s.label, items: s.pages.map((p) => ({ label: p.label, link: link(p) })) };
});

export default defineConfig({
  site: SITE,
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
  prefetch: false,
  devToolbar: { enabled: false },
  // esbuild keeps `animation-timeline` as its own declaration; Lightning CSS folds it into the `animation`
  // shorthand, which browsers reject, and the scroll-driven animations silently disappear.
  vite: { build: { cssMinify: 'esbuild' } },
  integrations: [
    starlight({
      title: 'kuukura',
      description: 'A self-hosted secrets vault for small teams. Values are decrypted only on your server.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: REPO_URL }],
      sidebar,
      customCss: ['./src/styles/tokens.css', './src/styles/starlight.css'],
      components: {
        SiteTitle: './src/components/starlight/SiteTitle.astro',
      },
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: `${SITE}/brand/social-preview.png` } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1280' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '640' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: `${SITE}/brand/social-preview.png` } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#061215' } },
      ],
      disable404Route: true,
      lastUpdated: false,
      credits: false,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
    }),
  ],
});
