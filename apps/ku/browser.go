package main

import (
	"os/exec"
	"runtime"
)

// openCommand is the program that opens a URL in the default browser on each OS.
func openCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		// not `cmd /c start`: the shell would treat & in the URL as a command separator
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

func openBrowser(url string) error {
	name, args := openCommand(runtime.GOOS, url)
	return exec.Command(name, args...).Start() // #nosec G204 -- fixed binary per OS, the URL is one argument
}
