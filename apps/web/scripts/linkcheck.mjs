// Checks every internal link and asset reference in dist/: the target file exists and, for #fragments, the id
// exists on that page. External links are listed, not fetched. Run after `pnpm build`.
import { readdir, readFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const DIST = resolve(import.meta.dirname, '../dist');

async function* walk(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.name.endsWith('.html')) yield p;
  }
}

/** The file a site path resolves to, or null. */
function fileFor(pathname) {
  const p = join(DIST, decodeURIComponent(pathname));
  if (existsSync(p) && statSync(p).isFile()) return p;
  const index = join(p, 'index.html');
  if (existsSync(index)) return index;
  return null;
}

const ids = new Map();
async function idsOf(file) {
  if (!ids.has(file)) {
    const html = await readFile(file, 'utf8');
    ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return ids.get(file);
}

let checked = 0;
const broken = [];
const external = new Set();
for await (const file of walk(DIST)) {
  const html = await readFile(file, 'utf8');
  const page = '/' + relative(DIST, file).replace(/index\.html$/, '').replace(/\\/g, '/');
  for (const m of html.matchAll(/\s(?:href|src)="([^"]+)"|\ssrcset="([^"]+)"/g)) {
    const urls = m[1] ? [m[1]] : m[2].split(',').map((s) => s.trim().split(/\s+/)[0]);
    for (const raw of urls) {
      const url = raw.replace(/&amp;/g, '&');
      if (/^(mailto:|data:|javascript:)/.test(url)) continue;
      if (/^https?:\/\//.test(url)) {
        external.add(url);
        continue;
      }
      checked++;
      const u = new URL(url, `http://site${page}`);
      const target = u.pathname === page && url.startsWith('#') ? file : fileFor(u.pathname);
      if (!target) {
        broken.push(`${page}: ${url} (no such page)`);
        continue;
      }
      const frag = decodeURIComponent(u.hash.slice(1));
      if (frag && target.endsWith('.html') && !(await idsOf(target)).has(frag)) {
        broken.push(`${page}: ${url} (no #${frag} there)`);
      }
    }
  }
}

console.log(`linkcheck: ${checked} internal links checked, ${external.size} external links not fetched`);
if (process.argv.includes('--external')) for (const u of [...external].sort()) console.log(`  ${u}`);
if (broken.length) {
  console.error(broken.map((b) => `  broken: ${b}`).join('\n'));
  process.exit(1);
}
