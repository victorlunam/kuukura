package storage_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/internal/storage"
	"github.com/victorlunam/kuukura/internal/storage/storagetest"
)

func TestNormalizeTags(t *testing.T) {
	got, err := storage.NormalizeTags([]string{"Env:Prod", "app:shop", "env:prod"})
	if err != nil || !slices.Equal(got, storage.Tags{"app:shop", "env:prod"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range [][]string{{"nocolon"}, {"a:b:c"}, {"a:"}, {"A B:c"}} {
		if _, err := storage.NormalizeTags(bad); err == nil {
			t.Fatalf("%v should be rejected", bad)
		}
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf("k:v%d", i)
	}
	if _, err := storage.NormalizeTags(many); err == nil {
		t.Fatal("11 tags should be rejected")
	}
}

// A secret value passed as a tag by mistake must not come back in the error.
func TestRejectedTagIsNotEchoed(t *testing.T) {
	const value = "sk_test_FAKE_EXAMPLE"
	_, err := storage.NormalizeTags([]string{"app:shop", value})
	if err == nil {
		t.Fatal("must be rejected")
	}
	if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(value)) || !strings.Contains(err.Error(), "2") {
		t.Fatalf("the error must name the position, not the input: %v", err)
	}
}

func TestTagsRoundTrip(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		for _, want := range []storage.Tags{{}, {"app:shop"}, {"app:shop", "env:prod", "team:pay"}} {
			id, err := newSecret(t, p, by, "RT_"+strings.ToUpper(strings.NewReplacer(":", "_", "-", "_").Replace(strings.Join(want, "_"))), want)
			if err != nil {
				t.Fatal(err)
			}
			var got storage.Tags
			if err := p.DB().QueryRow(p.Rebind(`SELECT tags FROM secrets WHERE id = ?`), id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		}
	})
}

// Excluding tags must give identical answers on both backends, including the prefix lookalike.
func TestTagExclusion(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		secrets := map[string]storage.Tags{
			"S_NONE":   {},
			"S_SHOP":   {"app:shop"},
			"S_WORKER": {"app:shop", "role:worker"},
			"S_BOTH":   {"app:shop", "role:worker", "team:pay"},
			"S_LOOK":   {"app:shop", "role:worker2"}, // prefix lookalike of role:worker
		}
		for n, tags := range secrets {
			if _, err := newSecret(t, p, by, n, tags); err != nil {
				t.Fatal(err)
			}
		}
		cases := []struct {
			sel  storage.Tags
			want []string
		}{
			{storage.Tags{}, []string{"S_BOTH", "S_LOOK", "S_NONE", "S_SHOP", "S_WORKER"}},
			{storage.Tags{"role:worker"}, []string{"S_LOOK", "S_NONE", "S_SHOP"}},
			{storage.Tags{"role:worker", "team:pay"}, []string{"S_LOOK", "S_NONE", "S_SHOP"}},
			{storage.Tags{"env:qa"}, []string{"S_BOTH", "S_LOOK", "S_NONE", "S_SHOP", "S_WORKER"}},
		}
		for _, c := range cases {
			cond, args := p.Excludes("tags", c.sel)
			rows, err := p.DB().Query(p.Rebind(`SELECT name FROM secrets WHERE `+cond+` ORDER BY name`), args...)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var n string
				if err := rows.Scan(&n); err != nil {
					t.Fatal(err)
				}
				got = append(got, n)
			}
			rows.Close()
			if !slices.Equal(got, c.want) {
				t.Fatalf("excluding %v: got %v want %v", c.sel, got, c.want)
			}
		}
	})
}

// Grant tag containment must give identical answers on both backends.
func TestGrantTagContainment(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, _ string, p storage.Provider) {
		by := newPrincipal(t, p)
		secrets := map[string]storage.Tags{
			"S_NONE":  {},
			"S_SHOP":  {"app:shop"},
			"S_PROD":  {"app:shop", "env:prod"},
			"S_PAY":   {"app:shop", "env:prod", "team:pay"},
			"S_OTHER": {"app:shop2", "env:prod"}, // prefix lookalike of app:shop
		}
		for n, tags := range secrets {
			if _, err := newSecret(t, p, by, n, tags); err != nil {
				t.Fatal(err)
			}
		}
		cases := []struct {
			sel  storage.Tags
			want []string
		}{
			{storage.Tags{}, []string{"S_NONE", "S_OTHER", "S_PAY", "S_PROD", "S_SHOP"}},
			{storage.Tags{"app:shop"}, []string{"S_PAY", "S_PROD", "S_SHOP"}},
			{storage.Tags{"app:shop", "env:prod"}, []string{"S_PAY", "S_PROD"}},
			{storage.Tags{"env:prod", "team:pay"}, []string{"S_PAY"}},
			{storage.Tags{"env:qa"}, nil},
		}
		for _, c := range cases {
			cond, args := p.Contains("tags", c.sel)
			rows, err := p.DB().Query(p.Rebind(`SELECT name FROM secrets WHERE `+cond+` ORDER BY name`), args...)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var n string
				if err := rows.Scan(&n); err != nil {
					t.Fatal(err)
				}
				got = append(got, n)
			}
			rows.Close()
			if !slices.Equal(got, c.want) {
				t.Fatalf("selector %v: got %v want %v", c.sel, got, c.want)
			}
		}
	})
}
