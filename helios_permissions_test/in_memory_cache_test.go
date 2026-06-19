package helios_permissions_test

import (
	"reflect"
	"sync"
	"testing"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

func mustEqual(t *testing.T, got, want []hp.Permission) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestInMemoryCache_Get_MissOnEmpty: brand new cache returns nil.
func TestInMemoryCache_Get_MissOnEmpty(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil on miss, got %v", got)
	}
}

// TestInMemoryCache_Set_ThenGet: round-trip.
func TestInMemoryCache_Set_ThenGet(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	perms := []hp.Permission{hp.PermissionAthensProjectView, hp.PermissionAthensProjectUpdate}
	if err := c.Set("u", "t", perms); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	mustEqual(t, got, perms)
}

// TestInMemoryCache_Set_NXSemantics: a second Set does not overwrite.
func TestInMemoryCache_Set_NXSemantics(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	first := []hp.Permission{hp.PermissionAthensProjectView}
	second := []hp.Permission{hp.PermissionAthensProjectUpdate}
	if err := c.Set("u", "t", first); err != nil {
		t.Fatal(err)
	}
	if err := c.Set("u", "t", second); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get("u", "t")
	mustEqual(t, got, first)
}

// TestInMemoryCache_WriteThrough_Overwrites: unlike Set, WriteThrough
// replaces.
func TestInMemoryCache_WriteThrough_Overwrites(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	if err := c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectUpdate}); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get("u", "t")
	mustEqual(t, got, []hp.Permission{hp.PermissionAthensProjectUpdate})
}

// TestInMemoryCache_Invalidate: drops a single entry.
func TestInMemoryCache_Invalidate(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	if err := c.Invalidate("u", "t"); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get("u", "t")
	if got != nil {
		t.Fatalf("expected nil after invalidate, got %v", got)
	}
}

// TestInMemoryCache_InvalidateTenant: drops every entry with the
// matching tenant suffix.
func TestInMemoryCache_InvalidateTenant(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	_ = c.Set("u1", "tA", []hp.Permission{hp.PermissionAthensProjectView})
	_ = c.Set("u2", "tA", []hp.Permission{hp.PermissionAthensProjectUpdate})
	_ = c.Set("u3", "tB", []hp.Permission{hp.PermissionMusePostsWrite})

	if err := c.InvalidateTenant("tA"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get("u1", "tA"); got != nil {
		t.Fatalf("u1/tA should be invalidated, got %v", got)
	}
	if got, _ := c.Get("u2", "tA"); got != nil {
		t.Fatalf("u2/tA should be invalidated, got %v", got)
	}
	if got, _ := c.Get("u3", "tB"); len(got) != 1 {
		t.Fatalf("u3/tB should still be present, got %v", got)
	}
}

// TestInMemoryCache_GetReturnsDefensiveCopy: caller mutating the
// returned slice must not mutate the cache.
func TestInMemoryCache_GetReturnsDefensiveCopy(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	got, _ := c.Get("u", "t")
	got[0] = hp.PermissionAthensProjectDelete
	again, _ := c.Get("u", "t")
	if again[0] != hp.PermissionAthensProjectView {
		t.Fatalf("cache was mutated by caller: %v", again)
	}
}

// TestInMemoryCache_ConcurrentReadersSingleWriter stress test: 50
// readers + a handful of writers in flight. Race detector should
// stay clean.
func TestInMemoryCache_ConcurrentReadersSingleWriter(t *testing.T) {
	c := hp.NewInMemoryPermissionCache()
	_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Get("u", "t")
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectUpdate})
		}()
	}
	wg.Wait()
}
