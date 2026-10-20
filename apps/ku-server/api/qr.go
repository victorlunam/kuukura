package api

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// qrSVG renders text as an inline SVG QR code (one path, no external resources).
func qrSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	var d strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Black(x, y) {
				continue
			}
			run := 1
			for x+run < c.Size && c.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&d, "M%d %dh%dv1h-%dz", x, y, run, run)
			x += run - 1
		}
	}
	n := c.Size
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 %d %d" shape-rendering="crispEdges"><path fill="#0b1220" d="%s"/></svg>`, n+4, n+4, d.String()), nil
}
