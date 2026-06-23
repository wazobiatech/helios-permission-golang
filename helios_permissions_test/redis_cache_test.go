package helios_permissions_test

import (
	"encoding/json"
	"testing"
	"time"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newMiniredisClient spins up a fresh miniredis + a real *redis.Client.
// Test is skipped if miniredis fails to start.
func newMiniredisClient(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Skipf("miniredis not available: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close(); mr.Close() })
	return mr, rdb
}

func TestRedisCache_Set_ThenGet(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{
		Client:     rdb,
		TTLSeconds: 60,
		Logger:     hp.SilentLogger(),
	})
	perms := []hp.Permission{hp.PermissionAthensProjectView, hp.PermissionAthensProjectUpdate}
	if err := c.Set("u", "t", perms); err != nil {
		t.Fatal(err)
	}
	// Confirm the key shape matches the cross-language contract.
	expected := hp.KeyPrefix + "u" + ":" + "t"
	if !mr.Exists(expected) {
		t.Fatalf("key %q should exist in Redis", expected)
	}
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != perms[0] || got[1] != perms[1] {
		t.Fatalf("got %v, want %v", got, perms)
	}
}

// TestRedisCache_KeyShape is the cross-language contract pinned
// against the Helios writer: helios:perms:{userId}:{tenantId}.
func TestRedisCache_KeyShape(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{
		Client:     rdb,
		Logger:     hp.SilentLogger(),
	})
	_ = c.WriteThrough("alice", "tenant-7", []hp.Permission{hp.PermissionAthensProjectView})
	raw, err := rdb.Get(t.Context(), "helios:perms:alice:tenant-7").Result()
	if err != nil {
		t.Fatalf("expected key to exist: %v", err)
	}
	var got []hp.Permission
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("value should be a JSON array of perms, got %q", raw)
	}
}

// TestRedisCache_Get_MissOnEmpty: brand new key, no entry.
func TestRedisCache_Get_MissOnEmpty(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil on miss, got %v", got)
	}
}

// TestRedisCache_SetNX: a second Set is a no-op (does not overwrite).
func TestRedisCache_SetNX(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	first := []hp.Permission{hp.PermissionAthensProjectView}
	second := []hp.Permission{hp.PermissionAthensProjectUpdate}
	_ = c.Set("u", "t", first)
	_ = c.Set("u", "t", second)
	got, _ := c.Get("u", "t")
	if len(got) != 1 || got[0] != hp.PermissionAthensProjectView {
		t.Fatalf("Set should be NX, got %v", got)
	}
}

// TestRedisCache_WriteThrough_Overwrites.
func TestRedisCache_WriteThrough_Overwrites(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	_ = c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	_ = c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectUpdate})
	got, _ := c.Get("u", "t")
	if len(got) != 1 || got[0] != hp.PermissionAthensProjectUpdate {
		t.Fatalf("WriteThrough should overwrite, got %v", got)
	}
}

// TestRedisCache_Invalidate drops a single key.
func TestRedisCache_Invalidate(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	_ = c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	if !mr.Exists("helios:perms:u:t") {
		t.Fatal("key should exist pre-invalidate")
	}
	if err := c.Invalidate("u", "t"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("helios:perms:u:t") {
		t.Fatal("key should be gone")
	}
}

// TestRedisCache_InvalidateTenant deletes only matching suffix.
func TestRedisCache_InvalidateTenant(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	_ = c.WriteThrough("u1", "tA", []hp.Permission{hp.PermissionAthensProjectView})
	_ = c.WriteThrough("u2", "tA", []hp.Permission{hp.PermissionAthensProjectView})
	_ = c.WriteThrough("u3", "tB", []hp.Permission{hp.PermissionAthensProjectView})
	if err := c.InvalidateTenant("tA"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get("u1", "tA"); got != nil {
		t.Fatalf("u1/tA should be gone")
	}
	if got, _ := c.Get("u2", "tA"); got != nil {
		t.Fatalf("u2/tA should be gone")
	}
	if got, _ := c.Get("u3", "tB"); len(got) != 1 {
		t.Fatalf("u3/tB should remain, got %v", got)
	}
}

// TestRedisCache_TTLExpire: miniredis fast-forwards time.
func TestRedisCache_TTLExpire(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, TTLSeconds: 60, Logger: hp.SilentLogger()})
	_ = c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	mr.FastForward(61 * time.Second)
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected TTL expiry, got %v", got)
	}
}

// TestRedisCache_Get_CorruptValueTreatedAsMiss: a non-array value
// should be treated as a miss (cache heals on the next Set).
func TestRedisCache_Get_CorruptValueTreatedAsMiss(t *testing.T) {
	_, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{Client: rdb, Logger: hp.SilentLogger()})
	_ = rdb.Set(t.Context(), "helios:perms:u:t", "not-an-array", 0).Err()
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected miss on corrupt value, got %v", got)
	}
}

// TestRedisCache_Defaults confirms the v0.2.0 no-TTL default and the
// cross-language key prefix.
func TestRedisCache_Defaults(t *testing.T) {
	if hp.DefaultCacheTTLSeconds != 0 {
		t.Fatalf("DefaultCacheTTLSeconds = %d, want 0 (no expiry)", hp.DefaultCacheTTLSeconds)
	}
	if hp.KeyPrefix != "helios:perms:" {
		t.Fatalf("KeyPrefix = %q, want helios:perms:", hp.KeyPrefix)
	}
}

// TestRedisCache_NoTTL_DefaultConstructor: building a cache without
// setting TTLSeconds defaults to 0 (no expiry). Entries persist until
// explicit DEL.
func TestRedisCache_NoTTL_DefaultConstructor(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{
		Client: rdb,
		Logger: hp.SilentLogger(),
	})
	if err := c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectView}); err != nil {
		t.Fatal(err)
	}
	// Fast-forwarding past any 60s safety net must NOT expire the key —
	// there is no TTL.
	mr.FastForward(120 * time.Second)
	got, err := c.Get("u", "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != hp.PermissionAthensProjectView {
		t.Fatalf("expected entry to persist past FastForward, got %v", got)
	}
}

// TestRedisCache_NoTTL_Set_NotSet: Set with the default (no-TTL)
// constructor writes a persistent key — miniredis's TTL is -1.
func TestRedisCache_NoTTL_Set_NotSet(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{
		Client: rdb,
		Logger: hp.SilentLogger(),
	})
	if err := c.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectView}); err != nil {
		t.Fatal(err)
	}
	ttl := mr.TTL("helios:perms:u:t")
	if ttl != 0 {
		// miniredis returns 0 for "no expiry set", matching Redis's PERSIST semantics.
		t.Fatalf("expected miniredis TTL=0 (no expiry), got %v", ttl)
	}
}

// TestRedisCache_NoTTL_OptInRestoresExpiry: passing a positive
// TTLSeconds restores the EX arg on writes.
func TestRedisCache_NoTTL_OptInRestoresExpiry(t *testing.T) {
	mr, rdb := newMiniredisClient(t)
	c := hp.NewRedisPermissionCache(hp.RedisCacheOptions{
		Client:     rdb,
		TTLSeconds: 120,
		Logger:     hp.SilentLogger(),
	})
	if err := c.WriteThrough("u", "t", []hp.Permission{hp.PermissionAthensProjectView}); err != nil {
		t.Fatal(err)
	}
	ttl := mr.TTL("helios:perms:u:t")
	if ttl <= 0 || ttl > 120*time.Second {
		t.Fatalf("expected positive TTL <= 120s, got %v", ttl)
	}
}
