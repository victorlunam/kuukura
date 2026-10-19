package auth

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is what an OIDC provider vouches for.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// AuthProvider is the login provider (Google today).
type AuthProvider interface {
	Name() string
	AuthURL(state, nonce, pkceVerifier string) string
	Exchange(ctx context.Context, code, pkceVerifier, nonce string) (Identity, error)
}

// Google is OIDC code flow with PKCE.
type Google struct {
	cfg      oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewGoogle(ctx context.Context, clientID, clientSecret, redirectURL string) (*Google, error) {
	p, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, err
	}
	return &Google{
		cfg: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email"}},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (g *Google) Name() string { return "google" }

func (g *Google) AuthURL(state, nonce, verifier string) string {
	// prompt=select_account: always show the account chooser, so a browser that is signed in to several Google
	// accounts never picks one silently (that would fail with an account that has no invite or identity).
	return g.cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"))
}

func (g *Google) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	tok, err := g.cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, err
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := g.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, err
	}
	if idt.Nonce != nonce {
		return Identity{}, errors.New("auth: nonce mismatch")
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idt.Claims(&c); err != nil {
		return Identity{}, err
	}
	return Identity{Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified}, nil
}
