# kuukura brand

**Idea:** an empty vault. The mark is the vault door seen front-on: a thick ring, eight bolts and one amber hub. It is a
door, not a wheel (no spokes), and it still reads at 16 px. The wordmark is lowercase `kuukura`, drawn in the same round
monoline as the ring. Nothing in the brand depends on a font, a script or a network request.

| Asset | File |
|---|---|
| Mark (app icon, 64x64 tile) | [`packages/brand/assets/mark.svg`](../packages/brand/assets/mark.svg) |
| Logo (mark + wordmark, light and dark aware) | [`packages/brand/assets/logo.svg`](../packages/brand/assets/logo.svg) |
| Favicon (simplified for 16/32 px, dark-mode tile) | [`packages/brand/assets/favicon.svg`](../packages/brand/assets/favicon.svg) |
| Banner (1280x640, README hero) | [`packages/brand/assets/banner.svg`](../packages/brand/assets/banner.svg) |
| Social preview (the banner rendered, 1280x640 PNG) | [`docs/social-preview.png`](social-preview.png) |
| Illustrations: empty vault, passkey, shield, closed vault (done), alert, confirm | [`packages/brand/art/`](../packages/brand/art) |
| Icon sprite (Google, fingerprint, key, shield, copy, download, check, terminal, phone, lifebuoy) | [`packages/brand/sprite.svg`](../packages/brand/sprite.svg) |
| Design tokens (the palette below as CSS variables) | [`packages/brand/tokens.css`](../packages/brand/tokens.css) |
| Dokploy template logo (a copy of the mark) | [`deploy/dokploy/kuukura.svg`](../deploy/dokploy/kuukura.svg) |

The server serves the mark, logo, favicon and banner at `/favicon.svg` and `/assets/<name>.svg`. The pages use inline
SVG, system fonts and no external resources, so the strict CSP (`default-src 'none'`) still holds.

## Palette

One accent. The base is teal-ink; amber is the only highlight. Teal is the supporting hue for state (progress, success,
the fingerprint) and never decorates. These are the values of
[`packages/brand/tokens.css`](../packages/brand/tokens.css), which the server's
`style.css` repeats (a test keeps them equal); each art file and the CLI's "signed in" page repeat them.

| Token (css var) | Light | Dark | Use |
|---|---|---|---|
| ink (`--ink`) | `#0a1b20` | `#e9f3f2` | text, outlines, primary button |
| muted (`--muted`) | `#566870` | `#8fa5aa` | secondary text |
| surface (`--card` on `--bg`) | `#ffffff` on `#f1f5f5` | `#0c1d22` on `#061215` | card and page |
| line (`--line`) | `#dce5e6` | `#1a3036` | borders |
| soft / hollow (`--soft`, `--hollow`) | `#e3f1ee` / `#cde3df` | `#0f2e2e` / `#07201f` | picture fills, ground shadow |
| teal (`--acc`) | `#0e9384` | `#2dd4bf` | state: progress, check, fingerprint |
| **amber (`--amber`)** | `#f5a524` | `#fbbf24` | **the accent**: the hub, one sparkle, badges. Use sparingly |

Fixed colors (they do not change with the theme): tile `#071519` (`#16373d` for the tab icon and logo in dark mode),
mark foreground `#EAF4F2`, white on a teal badge, `#0a1b20` on an amber badge.

## Type

- Pages: the system UI stack (`system-ui, -apple-system, "Segoe UI", Roboto, ...`) and the system mono stack. No web fonts.
- Wordmark: outlined paths, never live text. Stroke 5, round caps and joins, x-height 19, ascender 31, stem gap 10, optical
  gaps 9 to 10.5. It is one path, shared by `logo.svg` and `banner.svg` (a test makes sure it stays identical).
- Banner copy (headline 64 semibold, line 27) and the `ku run` chip are live system text; they are the only text in the
  assets.

## Geometry

Mark, 64 grid:

- Tile: rx 14 (22%), ink, with a 1 px hairline inset at 14% of the foreground. Foreground `#EAF4F2`.
- Door ring: r 20, stroke 4.5. Bolts: eight round dots (stroke 4.2, zero length) on r 11.5, at the cardinal and diagonal
  points. Hub: amber, r 4.6. Everything is centered on (32, 32).
- Favicon: same tile, ring r 20 stroke 7, amber hub r 7, no bolts (they would turn to noise at 16 px).
- Wordmark sits with its x-height centered on the tile (baseline y 41.5), 20 px from the tile (logo viewBox 247x64).
- `mark.svg` is inlined in every page: it has no `<style>`, no ids and no gradients.

Illustrations (240x160):

- Outline 2.5, bolts 5.6 dots, badge ring 4 in the card color, fingerprint 3; round caps and joins everywhere.
- Every picture has the same ground shadow (soft, rx 74, ry 6.5) and the same extras: one amber sparkle (22 px) and two
  teal dots (r 3 and 2.5). The alert picture swaps the sparkle for its amber badge.
- Badges are r 18. Objects that are not a vault (phone, shield) sit on a soft circular halo (r 62).
- Corner radii: vault body 18, phone 16, feet 2.5, panels 8.
- The vault door is the mark, large: rim, eight bolts, hub. The empty vault shows the open doorway and the door edge-on
  with its amber hub; the shield carries the dial.
- Each file carries its own `<style>` (CSS variables, light and dark) so it renders alone; inside a page that `<style>` is
  stripped and the page CSS (`.s-*` / `.f-*`) themes the same classes.

Icons (sprite): 24x24, 2 px safe margin, stroke 1.75, round caps and joins, containers rx 3, `currentColor`. The Google
glyph is the one full-color symbol.

## Rules for new assets

- Colors come only from the tokens above. No gradients in the mark; the banner may use one soft teal glow.
- No external references, scripts, raster images or fonts inside any SVG.
- The mark's geometry is pinned in `apps/ku-server/api/art_test.go` and, for the CLI's "signed in" page, in `apps/ku/signedin_test.go`
  (it must match `mark.svg` exactly). Change the file and both tests together, then copy the mark to
  `deploy/dokploy/kuukura.svg` and update `signedin.go`.
- After changing the banner, render `docs/social-preview.png` again at exactly 1280x640 (it stays under 1 MB):
  `chrome --headless --screenshot=docs/social-preview.png --window-size=1280,640 packages/brand/assets/banner.svg`.

**Voice:** short, plain, calm. Say what happened and what to do next.
