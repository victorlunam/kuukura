package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"

	"github.com/victorlunam/kuukura/keys"
)

// runInit generates the master key once. It writes the key file (to mount as a
// Docker secret) and an age-encrypted copy for offline storage. The key is never printed.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	keyFile := fs.String("key-file", "", "where to write the master key file (mode 0600)")
	export := fs.String("export", "", "where to write the age-encrypted offline copy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *export == "" {
		return errors.New("usage: ku-server init --key-file <path> --export <path.age>")
	}
	pass, err := promptPassphrase()
	if err != nil {
		return err
	}
	key, err := keys.GenerateMasterKey(1)
	if err != nil {
		return err
	}
	exp, err := os.OpenFile(*export, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if err := keys.ExportMasterKey(exp, key, pass); err != nil {
		_ = exp.Close()
		_ = os.Remove(*export)
		return err
	}
	if err := exp.Close(); err != nil {
		return err
	}
	if err := writeNew(*keyFile, key); err != nil {
		_ = os.Remove(*export)
		return err
	}
	fmt.Println("Master key created. Store the offline copy (and its passphrase) somewhere safe; it is not shown again.")
	return nil
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func promptPassphrase() (string, error) {
	read := func(label string) (string, error) {
		fmt.Fprint(os.Stderr, label)
		b, err := term.ReadPassword(int(syscall.Stdin)) // #nosec G115 -- fd fits in int
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	a, err := read("Offline copy passphrase (min 12 chars): ")
	if err != nil {
		return "", err
	}
	b, err := read("Repeat passphrase: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("passphrases do not match")
	}
	return a, nil
}
