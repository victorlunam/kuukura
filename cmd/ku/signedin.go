package main

// signedInPage is what the browser shows after `ku login` completes on the local callback port.
// Self-contained (inline mark and styles), same look as the server pages.
const signedInPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>Signed in · kuukura</title>
<style>
:root{color-scheme:light dark;--bg:#f3f5f8;--card:#fff;--ink:#0b1220;--muted:#5a6578;--line:#e2e7ee;--acc:#0f9d8a}
@media(prefers-color-scheme:dark){:root{--bg:#080d16;--card:#101827;--ink:#eef2f7;--muted:#94a0b3;--line:#1e293b;--acc:#2dd4bf}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.c{width:100%;max-width:24rem;background:var(--card);border:1px solid var(--line);border-radius:22px;padding:32px 28px;text-align:center;box-shadow:0 12px 40px rgba(11,18,32,.08)}
.m{width:52px;height:52px;margin:0 auto 18px;display:block}
.k{width:60px;height:60px;border-radius:50%;background:var(--acc);display:grid;place-items:center;margin:0 auto 16px}
h1{font-size:1.5rem;letter-spacing:-.02em;margin:0 0 6px}p{margin:0;color:var(--muted)}
</style></head><body><main class="c">
<svg class="m" viewBox="0 0 64 64" fill="none" aria-label="kuukura"><rect width="64" height="64" rx="16" fill="#0B1220"/><circle cx="32" cy="32" r="17" stroke="#fff" stroke-width="3.5"/><circle cx="32" cy="32" r="8.5" stroke="#fff" stroke-opacity=".3" stroke-width="2" stroke-dasharray="3 4.2"/><circle cx="32" cy="15" r="3.2" fill="#F5A524"/></svg>
<div class="k"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12.5 4.5 4.5L19 7"/></svg></div>
<h1>You're signed in</h1><p>You can close this tab and go back to your terminal.</p>
</main></body></html>`
