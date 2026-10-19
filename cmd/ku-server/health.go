package main

import (
	"errors"
	"net"
	"net/http"
	"time"
)

// runHealthcheck is for the container HEALTHCHECK (the image has no curl): GET /healthz on the local listener.
func runHealthcheck() error {
	addr := env("VAULT_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("unhealthy")
	}
	return nil
}
