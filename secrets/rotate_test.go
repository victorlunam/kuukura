package secrets

import (
	"strings"
	"testing"

	"github.com/victorlunam/kuukura/keys"
	"github.com/victorlunam/kuukura/storage"
	"github.com/victorlunam/kuukura/storage/storagetest"
)

func TestCheckKeyAtStart(t *testing.T) {
	storagetest.Each(t, func(t *testing.T, kind string, p storage.Provider) {
		ctx := t.Context()
		e := setup(t, p)
		u := e.human("member")
		e.grant(u, "write", "app:shop")

		kf1, _ := keys.GenerateMasterKey(1)
		kp1, _ := keys.ParseMasterKeys(kf1)
		if has, err := New(p, kp1, e.log).HasVersions(ctx); err != nil || has {
			t.Fatalf("an empty database holds no encrypted data: %v %v", has, err)
		}
		if err := New(p, kp1, e.log).CheckKey(ctx); err != nil {
			t.Fatalf("nothing to check: %v", err)
		}
		if _, err := New(p, kp1, e.log).Set(ctx, u, SetInput{Name: "CHK", Tags: []string{"app:shop"}, Value: []byte(fakeValue), Create: true}); err != nil {
			t.Fatal(err)
		}
		if has, err := New(p, kp1, e.log).HasVersions(ctx); err != nil || !has {
			t.Fatalf("%v %v", has, err)
		}
		if err := New(p, kp1, e.log).CheckKey(ctx); err != nil {
			t.Fatalf("the right key passes: %v", err)
		}

		other, _ := keys.GenerateMasterKey(1)
		kpOther, _ := keys.ParseMasterKeys(other)
		err := New(p, kpOther, e.log).CheckKey(ctx)
		if err == nil || err.Error() != "the master key does not match the data (key manual:v1 cannot open it)" {
			t.Fatalf("a different key with the same version: %v", err)
		}
		k2, _ := keys.GenerateMasterKey(2)
		onlyV2, _ := keys.ParseMasterKeys(k2)
		if err := New(p, onlyV2, e.log).CheckKey(ctx); err == nil || !strings.Contains(err.Error(), "key manual:v1 cannot open it") {
			t.Fatalf("a ring without the stored version: %v", err)
		}
		if err := New(p, keys.Sealed{}, e.log).CheckKey(ctx); err == nil || strings.Contains(err.Error(), "does not match") {
			t.Fatalf("a missing key is not a mismatch: %v", err)
		}
	})
}
