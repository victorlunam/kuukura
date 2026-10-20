package main

import "os"

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the user chose this path
	if err != nil {
		return err
	}
	return fillPrivate(f, data)
}

// fillPrivate writes data to a freshly opened file, forces mode 0600 (an existing file keeps its old mode
// otherwise) and closes it.
func fillPrivate(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
