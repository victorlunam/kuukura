package storage

// Migrator lets the external tests roll migrations back and forward one at a time.
var Migrator = migrator

// Migrations is the embedded migration set, to check every file has its pair and rolls back.
var Migrations = migrations
