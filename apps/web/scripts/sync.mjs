// Prebuild: turns repository Markdown (docs/*.md, SECURITY.md, CHANGELOG.md, skills/kuukura/SKILL.md) into Starlight pages
// and copies the brand assets. The repository files stay the single source; everything written here is generated
// and gitignored.
//
// - The first `# H1` becomes the page title and is removed from the body.
// - Links between synced files become site routes; links to other repository files become GitHub URLs.
// - The deploy templates and the CLI command reference are generated from the files that define them.
//
// This is the only file that knows where the app sits in the repository. Paths below are relative to the app
// folder (the one holding package.json); moving the app means updating REPO_ROOT and nothing else.
// The brand comes from packages/brand (the @kuukura/brand workspace package), which Go embeds too.
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, posix, relative, resolve } from 'node:path';
import { REPO_URL, SIDEBAR } from '../site.config.mjs';

// ---- repository paths (relative to the app folder) ----
const REPO_ROOT = '../..';
const DOCS_DIR = `${REPO_ROOT}/docs`;
/** The brand package (@kuukura/brand): assets/ (mark, logo, favicon, banner), art/ and tokens.css. */
const BRAND_PKG = `${REPO_ROOT}/packages/brand`;
const BRAND_DIR = `${BRAND_PKG}/assets`;
const ART_DIR = `${BRAND_PKG}/art`;
const BRAND_TOKENS = `${BRAND_PKG}/tokens.css`;
const SOCIAL_PREVIEW = `${DOCS_DIR}/social-preview.png`;

/** Doc pages synced from repository files, by slug. Paths are relative to REPO_ROOT. */
const SOURCES = {
  install: 'docs/install.md',
  'local-testing': 'docs/local-testing.md',
  deploy: 'docs/deploy.md',
  agents: 'docs/agents.md',
  skill: 'skills/kuukura/SKILL.md',
  security: 'SECURITY.md',
  'threat-model': 'docs/threat-model.md',
  'asvs-l2': 'docs/asvs-l2.md',
  'runbook-key-rotation-drill': 'docs/runbook-key-rotation-drill.md',
  api: 'docs/api.md',
  brand: 'docs/brand.md',
  changelog: 'CHANGELOG.md',
};

/** The deploy templates shown on /docs/templates/, in order. Paths are relative to REPO_ROOT. */
const TEMPLATES = [
  { title: 'Docker Compose + Caddy (any VPS)', files: ['deploy/docker/docker-compose.yml', 'deploy/docker/.env.example'] },
  { title: 'Dokploy (Compose)', files: ['deploy/dokploy/docker-compose.yml'] },
  { title: 'Dokploy (template)', files: ['deploy/dokploy/template.toml', 'deploy/dokploy/meta.json'] },
  { title: 'Coolify', files: ['deploy/coolify/kuukura.yaml'] },
  { title: 'Render', files: ['render.yaml'] },
  { title: 'Docker Swarm / Portainer stack', files: ['deploy/swarm/stack.yml'] },
];

/** Where the two programs keep their help text (Go raw-string constants). Relative to REPO_ROOT. */
const HELP = {
  ku: { file: 'apps/ku/main.go', name: 'usage' },
  server: { file: 'apps/ku-server/main.go', name: 'helpText' },
};

/** The command groups of the reference page, by first word; each gets a heading and so an anchor. */
const KU_GROUPS = ['profile', 'secret', 'run', 'workspace', 'account'];
const SERVER_GROUPS = ['key', 'user', 'audit'];

// ---- app paths ----
const APP = resolve(import.meta.dirname, '..');
const ROOT = resolve(APP, REPO_ROOT);
const OUT_DOCS = join(APP, 'src/content/docs/docs');
const OUT_GEN = join(APP, 'src/generated');
const OUT_PUBLIC = join(APP, 'public/brand');
const LOCAL_INDEX = join(APP, 'src/docs/index.mdx');
const GENERATED = new Set(['templates', 'cli']);

export { ROOT as REPO_ROOT_ABS };

const BLOB = `${REPO_URL}/blob/main/`;
const TREE = `${REPO_URL}/tree/main/`;

const fail = (msg) => {
  console.error(`sync: ${msg}`);
  process.exit(1);
};

const yaml = (s) => JSON.stringify(s); // a JSON string is a valid YAML scalar

function frontmatter(fields) {
  const lines = Object.entries(fields)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}: ${typeof v === 'string' ? yaml(v) : v}`);
  return `---\n${lines.join('\n')}\n---\n`;
}

/** Plain text of the first paragraph, for the meta description. */
function describe(body) {
  const para = [];
  for (const line of body.split('\n')) {
    const t = line.trim();
    if (!t) {
      if (para.length) break;
      continue;
    }
    if (/^(#|```|\||[-*] |\d+\. |>|<)/.test(t)) {
      if (para.length) break;
      continue;
    }
    para.push(t);
  }
  let text = para
    .join(' ')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (text.length > 160) text = `${text.slice(0, 157).replace(/\s+\S*$/, '')}…`;
  return text || undefined;
}

async function isDir(p) {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

const routes = new Map(Object.entries(SOURCES).map(([slug, file]) => [file, `/docs/${slug}/`]));

/** Rewrites one link target found in `from` (a repository path). */
async function rewrite(target, from) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) return target;
  const [path, anchor] = target.split('#');
  const repoPath = posix.normalize(posix.join(posix.dirname(from), path)).replace(/\/$/, '');
  if (repoPath.startsWith('..')) fail(`${from}: link leaves the repository: ${target}`);
  const hash = anchor ? `#${anchor}` : '';
  if (routes.has(repoPath)) return routes.get(repoPath) + hash;
  const abs = join(ROOT, repoPath);
  if (!existsSync(abs)) fail(`${from}: broken link ${target}`);
  return ((await isDir(abs)) ? TREE : BLOB) + repoPath + hash;
}

/** Rewrites every inline link and image outside fenced code. */
async function rewriteLinks(md, from) {
  const out = [];
  let fence = null;
  for (const line of md.split('\n')) {
    const f = line.match(/^\s*(`{3,}|~{3,})/);
    if (f) {
      if (!fence) fence = f[1];
      else if (f[1].startsWith(fence)) fence = null;
      out.push(line);
      continue;
    }
    if (fence) {
      out.push(line);
      continue;
    }
    let next = line;
    for (const m of line.matchAll(/\]\(([^)\s]+)\)/g)) {
      const to = await rewrite(m[1], from);
      if (to !== m[1]) next = next.replace(`](${m[1]})`, `](${to})`);
    }
    out.push(next);
  }
  return out.join('\n');
}

async function syncFile(from) {
  let md = await readFile(join(ROOT, from), 'utf8');
  md = md.replace(/^---\n[\s\S]*?\n---\n/, ''); // SKILL.md carries its own frontmatter for agents
  const h1 = md.match(/^# (.+)$/m);
  if (!h1) fail(`${from} has no "# Title" line`);
  md = md.replace(h1[0], '').replace(/^\s+/, '');
  md = await rewriteLinks(md, from);
  const head = frontmatter({ title: h1[1].trim(), description: describe(md), editUrl: `${REPO_URL}/edit/main/${from}` });
  return `${head}\n<!-- Generated from ${from} by scripts/sync.mjs. Edit that file, not this one. -->\n\n${md}`;
}

const LANG = { '.yml': 'yaml', '.yaml': 'yaml', '.toml': 'toml', '.json': 'json', '.example': 'sh' };

async function templatesPage() {
  let body = `Every file below is read from the repository when the site is built, so it is the current template on
\`main\`. How to use each one, and which master-key setup it implies, is in
[Deploy with Docker](/docs/deploy/#deploy-targets). All values in the templates are fake examples.

The templates default to the image tag \`latest\`; set \`KUUKURA_VERSION\` (or the image tag) to a release to pin one in
production.
`;
  for (const t of TEMPLATES) {
    body += `\n## ${t.title}\n`;
    for (const f of t.files) {
      const src = (await readFile(join(ROOT, f), 'utf8')).replace(/\s+$/, '');
      const ext = f.slice(f.lastIndexOf('.'));
      const fence = '`'.repeat(Math.max(3, ...[...src.matchAll(/`+/g)].map((m) => m[0].length + 1)));
      // `wrap`: long lines and comments wrap instead of scrolling out of sight
      body += `\n${fence}${LANG[ext] ?? ''} title="${f}" wrap\n${src}\n${fence}\n\n[View ${f} on GitHub](${BLOB}${f})\n`;
    }
  }
  return `${frontmatter({
    title: 'Deploy templates',
    description: 'The Docker Compose, Dokploy, Coolify, Render and Docker Swarm templates, as they are in the repository.',
  })}\n${body}`;
}

/** Reads a Go raw-string constant (the help text) from a source file. */
async function goConst({ file, name }) {
  const src = await readFile(join(ROOT, file), 'utf8');
  const m = src.match(new RegExp(`const ${name} = \`([^\`]*)\``));
  if (!m) fail(`${file}: const ${name} not found`);
  return m[1];
}

/** The help text's command lines, as [command, description]. */
function helpRows(text) {
  const rows = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^ {2}(\S.*?)\s{2,}(\S.*)$/);
    if (m) rows.push([m[1], m[2]]);
  }
  if (rows.length < 5) fail('help text format changed');
  return rows;
}

const table = (rows) =>
  `| Command | What it does |\n|---|---|\n${rows.map(([c, d]) => `| \`${c.replace(/\|/g, '\\|')}\` | ${d} |`).join('\n')}`;

/**
 * The help text as a table per command group, each under its own heading (so it has an anchor). Commands whose
 * first word is not a group (login, link, version) lead in a table of their own.
 */
function helpTables(text, groups) {
  const rows = helpRows(text);
  const lead = rows.filter(([c]) => !groups.includes(c.split(' ')[0]));
  const parts = lead.length ? [table(lead)] : [];
  for (const g of groups) {
    const own = rows.filter(([c]) => c.split(' ')[0] === g);
    if (!own.length) fail(`help text has no "${g}" commands`);
    parts.push(`### ${g}\n\n${table(own)}`);
  }
  return parts.join('\n\n');
}

async function cliPage() {
  const ku = await goConst(HELP.ku);
  const srv = await goConst(HELP.server);
  const kuNote = ku
    .split('\n')
    .filter((l) => l && !l.startsWith(' ') && !l.startsWith('Usage:'))
    .join(' ')
    .replace('--profile <name>', '`--profile <name>`');
  return `${frontmatter({
    title: 'Command reference',
    description: 'Every ku and ku-server command, one noun-verb line each, as printed by their help.',
  })}
There are two programs. \`ku\` (also installed as \`kuukura\`) is the CLI for people and CI. \`ku-server\` is the server
and the operator's tool on the host. Both print this list with \`help\`; the tables below are read from their source
when the site is built.

**Start here:** add your server with [\`ku profile add\`](#profile), sign in with \`ku login\`, save a value with
[\`ku secret set\`](#secret), then start your app with [\`ku run\`](#run). Jump to a group:
${[...KU_GROUPS, ...SERVER_GROUPS].map((g) => `[${g}](#${g})`).join(' · ')}.

## ku

${kuNote}

A typical session:

\`\`\`sh wrap
ku profile add work --url https://vault.example.com   # the profile holds the server URL
ku login                                              # Google, then your passkey or authenticator app
ku secret set DATABASE_URL app:shop                   # the value comes from a hidden prompt
ku link shop                                          # this folder belongs to the "shop" app
ku run env:dev -- npm run dev                         # the command starts with its secrets in the environment
\`\`\`

Values are never arguments, stdout carries only data, and \`ku run\` refuses secret names that load code. The details
are in [What goes where](/docs/install/#what-goes-where) and the exit codes in
[Errors and exit codes](/docs/install/#errors-and-exit-codes). Passkeys and authenticator apps:
[Your passkeys and authenticator apps](/docs/install/#your-passkeys-and-authenticator-apps).

${helpTables(ku, KU_GROUPS)}

## ku-server

${helpTables(srv, SERVER_GROUPS)}

Run it inside the container, for example \`docker compose exec kuukura /ku-server user list\`. Every state change is
audited under the reserved \`ku-server\` principal. See [People from the host](/docs/deploy/#5-people-from-the-host-first-admin-lost-factors),
[the master key](/docs/deploy/#2-the-master-key) and the [key rotation drill](/docs/runbook-key-rotation-drill/).
`;
}

/**
 * The brand's two palettes as --brand-light-* and --brand-dark-*. packages/brand/tokens.css has a light :root block
 * and a prefers-color-scheme dark block that overrides it; the site picks its theme by attribute instead, so it needs
 * both sets at once. Read from the file, so the values cannot drift.
 */
async function brandThemes() {
  const css = await readFile(resolve(APP, BRAND_TOKENS), 'utf8');
  const vars = (block) => Object.fromEntries([...block.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  const dark = css.match(/@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}/);
  const light = css.match(/^:root\s*\{([^}]*)\}/m);
  if (!light || !dark) fail(`${BRAND_TOKENS}: expected a :root block and a prefers-color-scheme dark block`);
  const lightVars = vars(light[1]);
  const darkVars = { ...lightVars, ...vars(dark[1]) };
  const emit = (theme, set) =>
    Object.entries(set)
      .map(([k, v]) => `  --brand-${theme}-${k.slice(2)}: ${v};`)
      .join('\n');
  return `/* Generated from ${BRAND_TOKENS.replace('../../', '')} by scripts/sync.mjs. Do not edit. */\n:root {\n${emit('light', lightVars)}\n${emit('dark', darkVars)}\n}\n`;
}

/** The latest released version: the first dated `## [x.y.z] - date` heading of CHANGELOG.md (never "Unreleased"). */
async function latestRelease() {
  const md = await readFile(join(ROOT, SOURCES.changelog), 'utf8');
  const m = md.match(/^## \[(\d[^\]\s]*)\] - (\d{4}-\d{2}-\d{2})/m);
  if (!m) fail(`${SOURCES.changelog} has no dated "## [x.y.z] - date" heading`);
  return { version: m[1], date: m[2] };
}

async function main() {
  // Every doc must have a place, and every place a source.
  for (const f of await readdir(resolve(APP, DOCS_DIR))) {
    if (f.endsWith('.md') && !routes.has(`docs/${f}`)) fail(`docs/${f} has no slug in SOURCES`);
  }
  const pages = SIDEBAR.flatMap((s) => s.pages);
  for (const { slug } of pages) {
    if (slug && !(slug in SOURCES) && !GENERATED.has(slug)) fail(`sidebar page "${slug}" has no source`);
  }
  for (const slug of Object.keys(SOURCES)) {
    if (!pages.some((p) => p.slug === slug)) fail(`${SOURCES[slug]} is not in the sidebar (site.config.mjs)`);
  }

  await rm(OUT_DOCS, { recursive: true, force: true });
  await mkdir(OUT_DOCS, { recursive: true });
  for (const { slug } of pages) {
    if (!slug) await cp(LOCAL_INDEX, join(OUT_DOCS, 'index.mdx'));
    else if (slug === 'templates') await writeFile(join(OUT_DOCS, 'templates.md'), await templatesPage());
    else if (slug === 'cli') await writeFile(join(OUT_DOCS, 'cli.md'), await cliPage());
    else await writeFile(join(OUT_DOCS, `${slug}.md`), await syncFile(SOURCES[slug]));
  }

  // Brand: the package's own files, so the site and the product cannot drift apart.
  const brand = resolve(APP, BRAND_DIR);
  await rm(OUT_GEN, { recursive: true, force: true });
  await rm(OUT_PUBLIC, { recursive: true, force: true });
  await mkdir(OUT_PUBLIC, { recursive: true });
  await cp(brand, join(OUT_GEN, 'brand'), { recursive: true });
  await cp(resolve(APP, ART_DIR), join(OUT_GEN, 'art'), { recursive: true });
  await writeFile(join(OUT_GEN, 'brand-themes.css'), await brandThemes());
  await writeFile(join(OUT_GEN, 'release.json'), `${JSON.stringify(await latestRelease())}\n`);
  for (const f of await readdir(brand)) await cp(join(brand, f), join(OUT_PUBLIC, f));
  await cp(join(brand, 'favicon.svg'), join(APP, 'public/favicon.svg'));
  await cp(resolve(APP, SOCIAL_PREVIEW), join(OUT_PUBLIC, 'social-preview.png'));

  console.log(`sync: ${pages.length} doc pages, brand from ${relative(APP, brand)} (${(await readdir(brand)).length} files)`);
}

if (import.meta.main) await main();
