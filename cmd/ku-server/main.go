package main

import (
	"fmt"
	"os"
)

// version is set at release time: -ldflags "-X main.version=2026.10.0".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ku-server <serve|init|admin>")
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "healthcheck":
		return runHealthcheck()
	case "serve":
		return runServe(args[1:])
	case "init":
		return runInit(args[1:])
	case "admin":
		return runAdmin(args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}
