package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func manual(t *testing.T, versions ...int) *Manual {
	t.Helper()
	var all []byte
	for _, v := range versions {
		b, err := GenerateMasterKey(v)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	m, err := ParseMasterKeys(all)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseMasterKeysRejects(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	cases := map[string]string{
		"version 0":          "0:" + good,
		"negative version":   "-1:" + good,
		"not a version":      "x:" + good,
		"short key":          "1:" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"not base64":         "1:!!!",
		"duplicate version":  "1:" + good + "\n1:" + other,
		"empty":              "\n  \n",
		"bad second line":    "1:" + good + "\n2:short",
		"duplicate, spaced":  "2:" + good + "\n\n 2:" + other + "\n",
		"version no key":     "3:",
		"version only colon": ":",
	}
	for name, body := range cases {
		m, err := ParseMasterKeys([]byte(body))
		if err == nil {
			t.Errorf("%s: accepted (%v)", name, m)
			continue
		}
		if strings.Contains(err.Error(), good) || strings.Contains(err.Error(), other) {
			t.Errorf("%s: the error echoes key material: %v", name, err)
		}
	}
	m, err := ParseMasterKeys([]byte("1:" + good + "\n\n3:" + other + "\n"))
	if err != nil || m.Version() != 3 {
		t.Fatalf("a valid ring with a gap must load: %v", err)
	}
}

// A bare key (what a platform generates for an env var) is version 1 and unlocks what the same key in a key file
// unlocks.
func TestParseBareMasterKey(t *testing.T) {
	ctx := t.Context()
	raw := bytes.Repeat([]byte{7}, 32)
	b64 := base64.StdEncoding.EncodeToString(raw)
	ringed, err := ParseMasterKeys([]byte("1:" + b64))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	p, _ := Seal(ctx, ringed, id, 1, []byte(fakeValue))
	for name, body := range map[string]string{"base64": b64 + "\n", "hex": " " + hex.EncodeToString(raw) + " "} {
		m, err := ParseMasterKeys([]byte(body))
		if err != nil || m.Version() != 1 || m.KeyID() != "manual:v1" {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := Open(ctx, m, id, 1, p); err != nil || string(got) != fakeValue {
			t.Fatalf("%s: a bare key must open what version 1 sealed", name)
		}
	}
	for name, body := range map[string]string{
		"hex too short":    strings.Repeat("ab", 31),
		"hex not hex":      strings.Repeat("zz", 32),
		"base64 16 bytes":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"base64 url form":  strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))),
		"two bare lines":   b64 + "\n" + b64,
		"bare then ringed": b64 + "\n2:" + b64,
	} {
		if _, err := ParseMasterKeys([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), body) {
			t.Errorf("%s: the error echoes the input", name)
		}
	}
}

func TestRingRoundTrips(t *testing.T) {
	m := manual(t, 3, 1)
	again, err := ParseMasterKeys(m.Ring())
	if err != nil || again.Version() != 3 || !bytes.Equal(again.Ring(), m.Ring()) {
		t.Fatalf("the ring text must parse back to the same ring: %v", err)
	}
	if !strings.HasPrefix(string(m.Ring()), "1:") {
		t.Fatal("oldest version first")
	}
}
