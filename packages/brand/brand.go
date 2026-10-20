// Package brand is the single source of the kuukura brand: logo files, illustrations, the icon sprite and the
// design tokens. The server embeds them; the web app imports the same files through package.json.
package brand

import "embed"

// FS holds assets/, art/, sprite.svg and tokens.css.
//
//go:embed assets art sprite.svg tokens.css
var FS embed.FS
