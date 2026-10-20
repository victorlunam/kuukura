// Renders the server's real pages and screenshots them, light and dark, into src/assets/screens/.
// Needs Go and Google Chrome. Run from site/: `node scripts/screens.mjs`. The lossless WebP files are committed;
// Astro serves resized AVIF/WebP. Not part of the build.
//
// The pages come from TestRenderPreview (internal/api/preview_test.go), which writes each page as HTML. Its step-up
// page has no request behind it, so it carries no "what you are confirming" line; this script adds the exact markup
// that page.html renders for a reveal request (`: <b class="ask">Reveal NAME tags</b>`), with a fake secret name.
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import sharp from 'sharp';
import { launch } from './cdp.mjs';

const ROOT = resolve(import.meta.dirname, '../..');
const OUT = resolve(import.meta.dirname, '../src/assets/screens');
const PAGES = ['invite', 'enroll', 'stepup', 'done'];
const ASK = 'Reveal STRIPE_KEY app:shop env:prod';

const dir = await mkdtemp(join(tmpdir(), 'ku-preview-'));
execFileSync('go', ['test', './internal/api', '-run', '^TestRenderPreview$', '-count=1'], {
  cwd: ROOT,
  env: { ...process.env, KU_PREVIEW_DIR: dir },
  stdio: 'inherit',
});

const stepup = join(dir, 'stepup.html');
const html = await readFile(stepup, 'utf8');
const marker = 'asking you to confirm. ';
if (!html.includes(marker)) throw new Error('stepup.html changed: update the Ask patch in screens.mjs');
await writeFile(stepup, html.replace(marker, `asking you to confirm: <b class="ask">${ASK}</b>. `));

await mkdir(OUT, { recursive: true });
const browser = await launch();
try {
  const p = await browser.page();
  for (const dark of [true, false]) {
    for (const name of PAGES) {
      await p.viewport(390, 844, { dark, reducedMotion: true });
      await p.goto(pathToFileURL(join(dir, `${name}.html`)).href);
      const file = join(OUT, `${name}-${dark ? 'dark' : 'light'}.webp`);
      // lossless WebP keeps the UI crisp at a third of the PNG's size; Astro derives AVIF/WebP sizes from it
      await sharp(await p.shot()).webp({ lossless: true, effort: 6 }).toFile(file);
      console.log('wrote', file);
    }
  }
} finally {
  await browser.close();
}
