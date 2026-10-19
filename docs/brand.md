# kuukura brand

**Idea:** an empty vault. The door ring is closed around nothing, because kuukura never keeps your values in the open:
they are decrypted only on your server, and the CLI is just the way to ask for them. One amber dot marks the dial.

| Asset | File |
|---|---|
| Mark (app icon, 64x64) | [`api/web/assets/mark.svg`](../api/web/assets/mark.svg) |
| Logo (mark + wordmark, adapts to dark mode) | [`api/web/assets/logo.svg`](../api/web/assets/logo.svg) |
| Favicon (adapts to dark mode) | [`api/web/assets/favicon.svg`](../api/web/assets/favicon.svg) |
| Banner / social preview (1200x630) | [`api/web/assets/banner.svg`](../api/web/assets/banner.svg) |
| Illustrations: empty vault, passkey, shield, closed vault, alert, confirm | [`api/web/art/`](../api/web/art) |
| Icon sprite (Google, fingerprint, key, shield, copy, download, check, terminal, phone, lifebuoy) | [`api/web/sprite.svg`](../api/web/sprite.svg) |

The server serves the mark, logo, favicon and banner at `/favicon.svg` and `/assets/<name>.svg`. The pages use inline
SVG, system fonts and no external resources, so the strict CSP (`default-src 'none'`) still holds.

**Colors**

| Token | Light | Dark | Use |
|---|---|---|---|
| ink | `#0b1220` | `#eef2f7` | text, primary button, vault outline |
| accent (teal) | `#0f9d8a` | `#2dd4bf` | progress, fingerprint, check |
| amber | `#f5a524` | `#fbbf24` | the dial marker and sparkles (use sparingly) |
| surface | `#ffffff` on `#f3f5f8` | `#101827` on `#080d16` | card and page |

**Type:** the system UI stack for the pages; the wordmark prefers a rounded system face (`ui-rounded`, SF Pro Rounded, Nunito).
**Voice:** short, plain, calm. Say what happened and what to do next.
