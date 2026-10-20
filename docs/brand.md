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

**Type:** the system UI stack for the pages. The wordmark in the logo and banner is outlined monoline lettering (round caps, stroke
about 5 on an x-height of 19, hand-spaced), so it looks the same on every platform and never depends on an installed font.
The banner's two lines of copy are live system text.

**Drawing rules (illustrations, 240x160)**

- Outline 2.5, wheel spokes 3.4, badge ring 4 in the card color, fingerprint 3; round caps and joins everywhere.
- Every picture has the same ground shadow (soft, rx 74) and the same set of extras: one amber sparkle, two teal dots.
  Objects that are not a vault (phone, shield) also sit on a soft circular halo (r 62); vaults do not, their body is wide enough.
- Corner radii: vault body 18 (22 for the open one), phone 16, feet 2.5.
- Colors come only from the tokens above. Each file carries its own `<style>` so it renders alone, and the page CSS
  (`.s-*` / `.f-*`) themes it when inlined.
- The mark's geometry (ring r19, three spokes, hub r4.2) is pinned by `cmd/ku/signedin_test.go`; change both together.
- Icons (sprite) are 24x24, stroke 1.75, round caps and joins, `currentColor`.
**Voice:** short, plain, calm. Say what happened and what to do next.
