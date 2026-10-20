package main

import "html"

// signedInPage is what the browser shows once `ku login` has exchanged the code and saved the session.
func signedInPage(profile string) string {
	return loginResultPage(profile, "Signed in", "You're signed in", "You can close this tab and go back to your terminal.",
		"", `<path d="m5 12.5 4.5 4.5L19 7"/>`)
}

// signInFailedPage is what it shows when the exchange or the saving failed, so the tab never contradicts the terminal.
func signInFailedPage(profile string) string {
	return loginResultPage(profile, "Sign-in failed", "Sign-in did not finish", "Go back to your terminal and run ku login again.",
		" bad", `<path d="M7 7l10 10M17 7 7 17"/>`)
}

// loginResultPage is self-contained (inline mark and styles); same look and brand as the server's pages.
func loginResultPage(profile, title, heading, text, class, icon string) string {
	label := ""
	if profile != "" {
		label = `<small>` + html.EscapeString(profile) + `</small>`
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>` + title + ` · kuukura</title>
<style>
:root{color-scheme:light dark;--bg:#f3f5f8;--card:#fff;--ink:#0b1220;--muted:#5a6578;--line:#e2e7ee;--acc:#0f9d8a}
@media(prefers-color-scheme:dark){:root{--bg:#080d16;--card:#101827;--ink:#eef2f7;--muted:#94a0b3;--line:#1e293b;--acc:#2dd4bf}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.c{width:100%;max-width:26rem;background:var(--card);border:1px solid var(--line);border-radius:22px;padding:28px;box-shadow:0 12px 40px rgba(11,18,32,.08)}
.b{display:flex;align-items:center;gap:10px;margin:0 0 22px}.b svg{width:30px;height:30px;border-radius:9px}.b span{font-weight:700;letter-spacing:-.02em}.b small{margin-left:auto;color:var(--muted);font-size:.78rem}
.k{width:64px;height:64px;border-radius:50%;background:var(--acc);display:grid;place-items:center;margin:8px auto 18px}.k.bad{background:#d64545}
h1{font-size:1.6rem;letter-spacing:-.025em;margin:0 0 8px;text-align:center}p{margin:0;color:var(--muted);text-align:center}
</style></head><body><main class="c">
<div class="b"><svg viewBox="0 0 64 64" fill="none" aria-hidden="true"><rect width="64" height="64" rx="16" fill="#0B1220"/><rect x=".75" y=".75" width="62.5" height="62.5" rx="15.25" stroke="#fff" stroke-opacity=".12" stroke-width="1.5"/><circle cx="32" cy="32" r="19" stroke="#fff" stroke-width="3.5"/><path d="M32 21.5V32M41.1 37.25 32 32M22.9 37.25 32 32" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="32" cy="32" r="4.2" fill="#F5A524"/></svg><span>kuukura</span>` + label + `</div>
<div class="k` + class + `"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">` + icon + `</svg></div>
<h1>` + heading + `</h1><p>` + text + `</p>
</main></body></html>`
}
