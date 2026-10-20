// Site-wide settings shared by astro.config.mjs, the pages and scripts/sync.mjs. No repository paths here: where
// each page's content comes from is decided in scripts/sync.mjs.

/** The public address of the site. Override with SITE_URL at build time (for example a custom domain). */
export const SITE = process.env.SITE_URL || 'https://kuukura-main-landing.neodev-f72.workers.dev';

export const REPO_URL = 'https://github.com/victorlunam/kuukura';

/**
 * The docs sidebar, in order. `slug` is the route under /docs/ ('' is /docs/ itself). A section with one page of
 * the same name is shown as a plain link.
 * @type {{ label: string, pages: { slug: string, label: string }[] }[]}
 */
export const SIDEBAR = [
  {
    label: 'Getting started',
    pages: [
      { slug: '', label: 'Overview' },
      { slug: 'install', label: 'Install the CLI' },
      { slug: 'local-testing', label: 'Try it locally' },
    ],
  },
  {
    label: 'Deploy',
    pages: [
      { slug: 'deploy', label: 'Deploy with Docker' },
      { slug: 'templates', label: 'Deploy templates' },
    ],
  },
  {
    label: 'Using kuukura',
    pages: [
      { slug: 'cli', label: 'Command reference' },
      { slug: 'agents', label: 'Coding agents' },
      { slug: 'skill', label: 'Agent skill (SKILL.md)' },
    ],
  },
  {
    label: 'Security',
    pages: [
      { slug: 'security', label: 'Security policy' },
      { slug: 'threat-model', label: 'Threat model' },
      { slug: 'asvs-l2', label: 'ASVS L2 self-review' },
    ],
  },
  { label: 'Operations', pages: [{ slug: 'runbook-key-rotation-drill', label: 'Key rotation drill' }] },
  {
    label: 'Reference',
    pages: [
      { slug: 'api', label: 'HTTP API' },
      { slug: 'brand', label: 'Brand' },
    ],
  },
  { label: 'Changelog', pages: [{ slug: 'changelog', label: 'Changelog' }] },
];
