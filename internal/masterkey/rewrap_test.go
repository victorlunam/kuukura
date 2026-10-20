package masterkey

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/victorlunam/kuukura/internal/access"
	"github.com/victorlunam/kuukura/internal/audit"
	"github.com/victorlunam/kuukura/internal/auth"
	"github.com/victorlunam/kuukura/internal/keys"
	"github.com/victorlunam/kuukura/internal/secrets"
	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

const fakeValue = "sk_test_FAKE_EXAMPLE"

func services(t *testing.T, p storage.Provider, kp keys.KeyProvider, log *audit.Log) (*secrets.Service, *auth.Service) {
	t.Helper()
	authSvc, err := auth.NewService(p, log, auth.NewTokens(p), nil, kp, auth.Config{RPID: "vault.example.test", RPOrigin: "https://vault.example.test", Issuer: "kuukura"})
	if err != nil {
		t.Fatal(err)
	}
	return secrets.New(p, kp, log), authSvc
}

func TestRewrapMovesEverythingToTheActiveKeyAndAudits(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		log := audit.New(p)
		member, admin := storagetest.Principal(t, p, "human", "member", "active"), storagetest.Principal(t, p, "human", "admin", "active")
		sel, err := storage.NormalizeTags([]string{"app:shop"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.DB().Exec(p.Rebind(`INSERT INTO grants (id, subject_type, subject_id, tag_selector, permission) VALUES (?, 'principal', ?, ?, 'write')`),
			uuid.New(), member, p.TagsArg(sel)); err != nil {
			t.Fatal(err)
		}
		u := access.Actor{ID: member, IP: "203.0.113.1"}

		kf1, _ := keys.GenerateMasterKey(1)
		kp1, _ := keys.ParseMasterKeys(kf1)
		k2, _ := keys.GenerateMasterKey(2)
		ring, err := keys.ParseMasterKeys(append(append([]byte{}, kf1...), k2...))
		if err != nil {
			t.Fatal(err)
		}
		sec1, _ := services(t, p, kp1, log)
		sec2, auth2 := services(t, p, ring, log)
		if _, err := sec1.Set(ctx, u, secrets.SetInput{Name: "ROT", Tags: []string{"app:shop"}, Value: []byte(fakeValue), Create: true}); err != nil {
			t.Fatal(err)
		}
		var before []byte
		if err := p.DB().QueryRow(`SELECT ciphertext FROM secret_versions`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if v, err := sec2.Reveal(ctx, u, secrets.Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fakeValue {
			t.Fatalf("data stays readable with the extended ring: %v", err)
		}

		// A rewrap that fails leaves no audit row: the row and the rewrap commit together.
		onlyV2, _ := keys.ParseMasterKeys(k2)
		secOnly, authOnly := services(t, p, onlyV2, log)
		if _, _, err := Rewrap(ctx, p, secOnly, authOnly, admin); err == nil {
			t.Fatal("a ring without the key of existing data must fail")
		}
		if n := rotations(t, log); len(n) != 0 {
			t.Fatal("a failed rewrap must not be audited as a rotation")
		}

		// Two authenticator apps sealed under key 1, in the format auth stores them.
		for range 2 {
			owner := storagetest.Principal(t, p, "human", "member", "active")
			w, err := kp1.Wrap(ctx, []byte("JBSWY3DPEHPK3PXP"), append([]byte("kuukura-totp\x00"), owner[:]...))
			if err != nil {
				t.Fatal(err)
			}
			enc := append(append([]byte{byte(len(kp1.KeyID()))}, kp1.KeyID()...), w...)
			if _, err := p.DB().Exec(p.Rebind(`INSERT INTO credentials (id, principal_id, kind, encrypted_totp_secret, is_default) VALUES (?, ?, 'totp', ?, ?)`),
				uuid.New(), owner, enc, true); err != nil {
				t.Fatal(err)
			}
		}

		nSecrets, nTOTP, err := Rewrap(ctx, p, sec2, auth2, admin)
		if err != nil || nSecrets != 1 || nTOTP != 2 {
			t.Fatalf("rewrapped %d secret versions and %d TOTP secrets: %v", nSecrets, nTOTP, err)
		}
		var keyID string
		var after []byte
		if err := p.DB().QueryRow(`SELECT key_id, ciphertext FROM secret_versions`).Scan(&keyID, &after); err != nil {
			t.Fatal(err)
		}
		if keyID != "manual:v2" || !bytes.Equal(before, after) {
			t.Fatalf("key_id %s, ciphertext changed: %v", keyID, !bytes.Equal(before, after))
		}
		rows, err := p.DB().Query(`SELECT encrypted_totp_secret FROM credentials WHERE kind = 'totp'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var enc []byte
			if err := rows.Scan(&enc); err != nil {
				t.Fatal(err)
			}
			if got := string(enc[1 : 1+int(enc[0])]); got != "manual:v2" {
				t.Fatalf("a TOTP secret is still on key %s", got)
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		rot := rotations(t, log)
		if len(rot) != 1 || rot[0].Principal != admin || rot[0].TargetType != "key" || rot[0].Metadata["key_id"] != "manual:v2" ||
			fmt.Sprint(rot[0].Metadata["secret_versions"]) != "1" || fmt.Sprint(rot[0].Metadata["totp"]) != "2" {
			t.Fatalf("the rotation must be audited once, with its counts: %+v", rot)
		}
		if v, err := sec2.Reveal(ctx, u, secrets.Selector{Name: "ROT"}, true); err != nil || string(v.Data) != fakeValue {
			t.Fatalf("readable after rewrap: %v", err)
		}
		if n, m, _ := Rewrap(ctx, p, sec2, auth2, admin); n != 0 || m != 0 {
			t.Fatal("nothing left to rewrap")
		}
		if err := log.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func rotations(t *testing.T, log *audit.Log) []audit.Row {
	t.Helper()
	rows, err := log.List(t.Context(), audit.Filter{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	var rot []audit.Row
	for _, r := range rows {
		if r.Action == "key_rotate" {
			rot = append(rot, r)
		}
	}
	return rot
}
