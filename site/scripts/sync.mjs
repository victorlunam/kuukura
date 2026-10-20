// Prebuild: turns the repository's Markdown (docs/*.md, SECURITY.md, CHANGELOG.md, SKILL.md) into Starlight pages
// and copies the brand assets. The repository files stay the single source; everything written here is generated
// and gitignored.
//
// - The first `# H1` becomes the page title and is removed from the body.
// - Links between synced files become site routes; links to other repository files become GitHub URLs.
// - The deploy templates and the CLI command reference are generated from the files that define them.
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, posix, relative, resolve } from 'node:path';
import { REPO, SECTIONS, TEMPLATES } from '../docs.config.mjs';

/** The server's brand assets (mark, logo, favicon, banner). The art lives next to it in ../art. */
const BRAND_DIR = '../internal/api/web/assets';

const SITE_DIR = resolve(import.meta.dirname, '..');
const ROOT = resolve(SITE_DIR, '..');
const OUT_DOCS = join(SITE_DIR, 'src/content/docs/docs');
const OUT_GEN = join(SITE_DIR, 'src/generated');
const OUT_PUBLIC = join(SITE_DIR, 'public/brand');
const LOCAL_DOCS = join(SITE_DIR, 'src/docs');
const BLOB = `${REPO}/blob/main/`;
const TREE = `${REPO}/tree/main/`;

const pages = SECTIONS.flatMap((s) => s.pages);
/** repository path (posix) -> site route */
const routes = new Map(pages.filter((p) => p.from).map((p) => [p.from, `/docs/${p.slug}/`]));

const fail = (msg) => {
  console.error(`sync: ${msg}`);
  process.exit(1);
};

// Every doc must have a place on the site.
for (const f of await readdir(join(ROOT, 'docs'))) {
  if (f.endsWith('.md') && !routes.has(`docs/${f}`)) fail(`docs/${f} is not placed in site/docs.config.mjs`);
}

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

async function syncFile(page) {
  let md = await readFile(join(ROOT, page.from), 'utf8');
  md = md.replace(/^---\n[\s\S]*?\n---\n/, ''); // SKILL.md carries its own frontmatter for agents
  const h1 = md.match(/^# (.+)$/m);
  if (!h1) fail(`${page.from} has no "# Title" line`);
  md = md.replace(h1[0], '').replace(/^\s+/, '');
  md = await rewriteLinks(md, page.from);
  const head = frontmatter({
    title: h1[1].trim(),
    description: describe(md),
    editUrl: `${REPO}/edit/main/${page.from}`,
  });
  return `${head}\n<!-- Generated from ${page.from} by site/scripts/sync.mjs. Edit that file, not this one. -->\n\n${md}`;
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
      body += `\n${fence}${LANG[ext] ?? ''} title="${f}"\n${src}\n${fence}\n\n[View ${f} on GitHub](${BLOB}${f})\n`;
    }
  }
  return `${frontmatter({
    title: 'Deploy templates',
    description: 'The Docker Compose, Dokploy, Coolify, Render and Docker Swarm templates, as they are in the repository.',
  })}\n${body}`;
}

/** Reads a Go raw-string constant (the help text) from a source file. */
async function goConst(file, name) {
  const src = await readFile(join(ROOT, file), 'utf8');
  const m = src.match(new RegExp(`const ${name} = \`([^\`]*)\``));
  if (!m) fail(`${file}: const ${name} not found`);
  return m[1];
}

function helpTable(text) {
  const rows = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^ {2}(\S.*?)\s{2,}(\S.*)$/);
    if (m) rows.push(`| \`${m[1].replace(/\|/g, '\\|')}\` | ${m[2]} |`);
  }
  if (rows.length < 5) fail('help text format changed');
  return `| Command | What it does |\n|---|---|\n${rows.join('\n')}`;
}

async function cliPage() {
  const ku = await goConst('cmd/ku/main.go', 'usage');
  const srv = await goConst('cmd/ku-server/main.go', 'helpText');
  const kuNote = ku
    .split('\n')
    .filter((l) => l && !l.startsWith(' ') && !l.startsWith('Usage:'))
    .join(' ');
  return `${frontmatter({
    title: 'Command reference',
    description: 'Every ku and ku-server command, one noun-verb line each, as printed by their help.',
  })}
There are two programs. \`ku\` (also installed as \`kuukura\`) is the CLI for people and CI. \`ku-server\` is the server
and the operator's tool on the host. Both print this list with \`help\`; the tables below are read from their source
when the site is built.

## ku

${helpTable(ku)}

${kuNote}

A typical session:

\`\`\`sh
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

## ku-server

${helpTable(srv)}

Run it inside the container, for example \`docker compose exec kuukura /ku-server user list\`. Every state change is
audited under the reserved \`ku-server\` principal. See [People from the host](/docs/deploy/#5-people-from-the-host-first-admin-lost-factors),
[the master key](/docs/deploy/#2-the-master-key) and the [key rotation drill](/docs/runbook-key-rotation-drill/).
`;
}

// ---- write ----
await rm(OUT_DOCS, { recursive: true, force: true });
await mkdir(OUT_DOCS, { recursive: true });
for (const page of pages) {
  if (page.local) {
    await cp(join(LOCAL_DOCS, page.local), join(OUT_DOCS, page.slug ? `${page.slug}.mdx` : page.local));
    continue;
  }
  const content = page.from ? await syncFile(page) : page.generated === 'templates' ? await templatesPage() : await cliPage();
  await writeFile(join(OUT_DOCS, `${page.slug}.md`), content);
}

// Brand: the server's own files, so the site and the product cannot drift apart.
const brand = resolve(SITE_DIR, BRAND_DIR);
const art = resolve(brand, '../art');
await rm(OUT_GEN, { recursive: true, force: true });
await rm(OUT_PUBLIC, { recursive: true, force: true });
await mkdir(OUT_PUBLIC, { recursive: true });
await cp(brand, join(OUT_GEN, 'brand'), { recursive: true });
await cp(art, join(OUT_GEN, 'art'), { recursive: true });
await cp(resolve(brand, '../sprite.svg'), join(OUT_GEN, 'sprite.svg'));
for (const f of await readdir(brand)) await cp(join(brand, f), join(OUT_PUBLIC, f));
await cp(join(brand, 'favicon.svg'), join(SITE_DIR, 'public/favicon.svg'));
await cp(join(ROOT, 'docs/social-preview.png'), join(OUT_PUBLIC, 'social-preview.png'));

console.log(
  `sync: ${pages.length} doc pages, brand from ${relative(SITE_DIR, brand)} (${(await readdir(brand)).length} files)`,
);
