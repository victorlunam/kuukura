// Package db embeds the dbmate migrations, one set per dialect.
package db

import "embed"

//go:embed migrations
var Migrations embed.FS
