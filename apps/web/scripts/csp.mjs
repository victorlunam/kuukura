// Run after `astro build`: fills the Content-Security-Policy placeholders in dist/_headers.
// Astro's built-in `security.csp` only hashes what Astro itself bundles; Starlight emits its own inline scripts
// and <style> blocks (theme init, search, Expressive Code), so instead every inline <script> and <style> in the
// built pages is hashed here (sha256) and the union goes into one site-wide header. The policy text lives in
// public/_headers. Style *attributes* (custom properties only) cannot be hashed; they are allowed by
// style-src-attr alone, which grants no script execution.
import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const DIST = resolve(import.meta.dirname, '../dist');

async function* walk(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.name.endsWith('.html')) yield p;
  }
}

const scripts = new Set();
const styles = new Set();
const hash = (body) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`;

for await (const file of walk(DIST)) {
  const html = await readFile(file, 'utf8');
  // Inline blocks only: a <script src=...> is covered by 'self'.
  for (const m of html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)) if (m[1]) scripts.add(hash(m[1]));
  for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) if (m[1]) styles.add(hash(m[1]));
}

const headersPath = join(DIST, '_headers');
let headers = await readFile(headersPath, 'utf8');
if (!headers.includes('__SCRIPT_HASHES__')) throw new Error('dist/_headers has no __SCRIPT_HASHES__ placeholder');
headers = headers.replace('__SCRIPT_HASHES__', [...scripts].sort().join(' ')).replace('__STYLE_HASHES__', [...styles].sort().join(' '));
await writeFile(headersPath, headers);
console.log(`csp: ${scripts.size} inline script hashes, ${styles.size} inline style hashes`);
