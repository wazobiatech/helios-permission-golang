package helios_permissions_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

// heliosFixture is a per-test HTTP server that returns a configurable
// response. The hit counter lets tests assert that the cache layer
// is actually preventing the second read from hitting the wire.
type heliosFixture struct {
	srv     *httptest.Server
	hits    int32
	handler func(w http.ResponseWriter, r *http.Request)
}

func newHeliosFixture(t *testing.T, handler http.HandlerFunc) *heliosFixture {
	t.Helper()
	f := &heliosFixture{handler: handler}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.hits, 1)
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"active","role":"EDITOR","permissions":["athens:project:view"]}`)
	}))
	return f
}

func (f *heliosFixture) close() { f.srv.Close() }

func (f *heliosFixture) client() *hp.HeliosClient {
	return hp.NewHeliosClient(hp.HeliosClientOptions{
		BaseURL:              f.srv.URL,
		SignatureSharedSecret: "test",
		HTTPClient:           f.srv.Client(),
		Now:                  frozenNow(),
	})
}

// testClient builds a Client backed by an in-memory cache and the
// given Helios transport.
func testClient(h *hp.HeliosClient, staleOnError *bool) (hp.Client, *hp.InMemoryPermissionCache) {
	cache := hp.NewInMemoryPermissionCache()
	c, err := hp.NewClient(hp.ClientOptions{
		Cache:        cache,
		Helios:       h,
		StaleOnError: staleOnError,
		Logger:       hp.SilentLogger(),
	})
	if err != nil {
		panic(err)
	}
	return c, cache
}

// TestCallerHasPermission_CacheHit verifies a second call within
// the cache lifetime does NOT re-hit Helios.
//
// Note: we use PermissionAthensProjectDelete (OWNER-only) instead of
// PermissionAthensProjectView because the latter is universal-by-contract
// (granted to every role) and short-circuits in v0.7.0 without ever
// consulting the cache. The cache-hit semantics this test is exercising
// require a non-universal perm.
func TestCallerHasPermission_CacheHit(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"active","role":"OWNER","permissions":["athens:project:delete"]}`)
	})
	defer f.close()

	c, _ := testClient(f.client(), nil)
	ctx := context.Background()

	allowed, err := c.CallerHasPermission(ctx, "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected allowed")
	}
	if atomic.LoadInt32(&f.hits) != 1 {
		t.Fatalf("first call should hit Helios once, got %d", f.hits)
	}
	allowed2, err := c.CallerHasPermission(ctx, "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed2 {
		t.Fatal("expected allowed (cache hit)")
	}
	if atomic.LoadInt32(&f.hits) != 1 {
		t.Fatalf("second call should be a cache hit, but hits=%d", f.hits)
	}
}

// TestCallerHasPermission_CacheMiss_HeliosOK: write-through the
// perm array to the cache after a successful fetch.
//
// Uses PermissionAthensProjectDelete (OWNER-only) to bypass the
// universal short-circuit.
func TestCallerHasPermission_CacheMiss_HeliosOK(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"active","role":"OWNER","permissions":["athens:project:delete"]}`)
	})
	defer f.close()
	c, cache := testClient(f.client(), nil)

	allowed, err := c.CallerHasPermission(context.Background(), "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil || !allowed {
		t.Fatalf("expected allowed, got allowed=%v err=%v", allowed, err)
	}
	cached, _ := cache.Get("u", "t")
	if len(cached) != 1 || cached[0] != hp.PermissionAthensProjectDelete {
		t.Fatalf("cache should contain the fetched perms, got %v", cached)
	}
}

// TestCallerHasPermission_NotMember_CachesEmpty: 404 → empty perms
// cached and returned.
//
// Uses PermissionAthensProjectDelete (OWNER-only) to bypass the
// universal short-circuit.
func TestCallerHasPermission_NotMember_CachesEmpty(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	})
	defer f.close()
	c, cache := testClient(f.client(), nil)

	allowed, err := c.CallerHasPermission(context.Background(), "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("expected denied for not_a_member")
	}
	cached, _ := cache.Get("u", "t")
	if cached == nil {
		t.Fatal("cache should hold an empty slice for not_a_member, not nil")
	}
	if len(cached) != 0 {
		t.Fatalf("expected empty perms, got %v", cached)
	}
}

// TestCallerHasPermission_StaleOnError_True: on Helios error, return
// the cached value (fail-closed allow-stale).
//
// Uses PermissionAthensProjectDelete (OWNER-only) to bypass the
// universal short-circuit.
func TestCallerHasPermission_StaleOnError_True(t *testing.T) {
	// First call populates the cache.
	ok := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"active","role":"OWNER","permissions":["athens:project:delete"]}`)
	})
	defer ok.close()
	c, _ := testClient(ok.client(), nil)
	_, err := c.CallerHasPermission(context.Background(), "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil {
		t.Fatal(err)
	}

	// Now switch the Helios transport to a server that always errors.
	bad := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	})
	defer bad.close()

	// Rewire the client's helios by re-creating against the bad fixture.
	// Same cache (manually share by building a new client on top).
	cache := hp.NewInMemoryPermissionCache()
	_ = cache.Set("u", "t", []hp.Permission{hp.PermissionAthensProjectDelete})
	cli, _ := hp.NewClient(hp.ClientOptions{
		Cache:        cache,
		Helios:       bad.client(),
		StaleOnError: ptrBool(true),
		Logger:       hp.SilentLogger(),
	})
	allowed, err := cli.CallerHasPermission(context.Background(), "u", "t", hp.PermissionAthensProjectDelete)
	if err != nil {
		t.Fatalf("with staleOnError=true, error should be swallowed: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed from cache (stale-on-error)")
	}
}

// TestCallerHasPermission_StaleOnError_False: on Helios error,
// propagate the error when no fresh value is available.
//
// Uses PermissionAthensProjectDelete (OWNER-only) to bypass the
// universal short-circuit.
func TestCallerHasPermission_StaleOnError_False(t *testing.T) {
	bad := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	})
	defer bad.close()
	cache := hp.NewInMemoryPermissionCache() // empty
	cli, _ := hp.NewClient(hp.ClientOptions{
		Cache:        cache,
		Helios:       bad.client(),
		StaleOnError: ptrBool(false),
		Logger:       hp.SilentLogger(),
	})
	_, err := cli.CallerHasPermission(context.Background(), "u", "t", hp.PermissionAthensProjectDelete)
	if err == nil {
		t.Fatal("expected error to propagate when staleOnError=false and no cache")
	}
	if !hp.IsHeliosUnreachableError(err) {
		t.Fatalf("expected HeliosUnreachableError, got %T: %v", err, err)
	}
}

// TestGetUserPermissions returns the full perm array.
//
// v0.7.0 folds SELF_PERMISSIONS into the result, so we now see the 3
// role perms + every self-scope perm. Just verify the expected
// presence/absence.
func TestGetUserPermissions(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"status": "active",
			"role": "OWNER",
			"permissions": ["athens:project:view", "athens:project:update", "helios:tenant:switch:self"]
		}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)
	got, err := c.GetUserPermissions(context.Background(), "u", "t")
	if err != nil {
		t.Fatal(err)
	}
	wantPresent := []hp.Permission{
		hp.PermissionAthensProjectView,
		hp.PermissionAthensProjectUpdate,
		hp.PermissionHeliosTenantSwitchSelf,
		hp.PermissionMercuryUserReadSelf,   // self-scope (folded in)
		hp.PermissionMercuryUserWriteSelf,  // self-scope (folded in)
		hp.PermissionMercuryUserDeleteSelf, // self-scope (folded in)
	}
	for _, want := range wantPresent {
		found := false
		for _, p := range got {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %s in perms, got: %v", want, got)
		}
	}
}

// TestExplain covers both branches.
func TestExplain(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"active","role":"EDITOR","permissions":["athens:project:view"]}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)
	exp, err := c.Explain(context.Background(), "u", "t", hp.PermissionAthensProjectView)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Allowed || exp.Reason != "granted_by_role" {
		t.Fatalf("unexpected explanation: %+v", exp)
	}

	exp2, err := c.Explain(context.Background(), "u", "t", hp.PermissionAthensProjectUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if exp2.Allowed || exp2.Reason != "not_in_role_perm_set" {
		t.Fatalf("unexpected explanation: %+v", exp2)
	}
}

// TestWriteThrough_AndInvalidate flow.
func TestWriteThrough_AndInvalidate(t *testing.T) {
	cache := hp.NewInMemoryPermissionCache()
	f := newHeliosFixture(t, nil)
	defer f.close()
	c, _ := hp.NewClient(hp.ClientOptions{
		Cache:  cache,
		Helios: f.client(),
		Logger: hp.SilentLogger(),
	})
	_ = c.WriteThrough(context.Background(), "u", "t", []hp.Permission{hp.PermissionAthensProjectView})
	got, _ := cache.Get("u", "t")
	if len(got) != 1 {
		t.Fatalf("WriteThrough should populate the cache, got %v", got)
	}
	if err := c.Invalidate(context.Background(), "u", "t"); err != nil {
		t.Fatal(err)
	}
	got, _ = cache.Get("u", "t")
	if got != nil {
		t.Fatalf("Invalidate should drop, got %v", got)
	}
}

// TestInvalidateTenant_Flow.
func TestInvalidateTenant_Flow(t *testing.T) {
	cache := hp.NewInMemoryPermissionCache()
	_ = cache.Set("u1", "tA", []hp.Permission{hp.PermissionAthensProjectView})
	_ = cache.Set("u2", "tB", []hp.Permission{hp.PermissionAthensProjectView})
	f := newHeliosFixture(t, nil)
	defer f.close()
	c, _ := hp.NewClient(hp.ClientOptions{
		Cache:  cache,
		Helios: f.client(),
		Logger: hp.SilentLogger(),
	})
	if err := c.InvalidateTenant(context.Background(), "tA"); err != nil {
		t.Fatal(err)
	}
	if got, _ := cache.Get("u1", "tA"); got != nil {
		t.Fatalf("u1/tA should be invalidated")
	}
	if got, _ := cache.Get("u2", "tB"); len(got) != 1 {
		t.Fatalf("u2/tB should remain")
	}
}

// TestInFlight_Coalescing: 10 concurrent calls for the same key
// should result in at most a small number of upstream fetches.
func TestInFlight_Coalescing(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		// Tiny sleep so the requests overlap.
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, `{"status":"active","role":"VIEWER","permissions":[]}`)
	})
	defer f.close()

	c, _ := testClient(f.client(), nil)
	ctx := context.Background()
	const n = 10
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := c.CallerHasPermission(ctx, "u", "t", hp.PermissionAthensProjectView)
			errCh <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("call failed: %v", err)
		}
	}
	hits := atomic.LoadInt32(&f.hits)
	if hits > 2 {
		t.Fatalf("in-flight coalescing should limit upstream hits, got %d", hits)
	}
}

// TestNewClient_RequiresCache confirms a missing cache is rejected.
func TestNewClient_RequiresCache(t *testing.T) {
	_, err := hp.NewClient(hp.ClientOptions{
		Helios: &hp.HeliosClient{},
	})
	if err == nil {
		t.Fatal("expected error for missing cache")
	}
	if !errors.Is(err, err) { // smoke check; we just want non-nil
	}
}

// TestNewClient_RequiresHelios confirms a missing helios is rejected.
func TestNewClient_RequiresHelios(t *testing.T) {
	_, err := hp.NewClient(hp.ClientOptions{
		Cache: hp.NewInMemoryPermissionCache(),
	})
	if err == nil {
		t.Fatal("expected error for missing helios")
	}
}

func ptrBool(b bool) *bool { return &b }

// --- v0.7.0 short-circuit tests ----------------------------------------
//
// v0.7.0 adds a universal-by-contract short-circuit to CallerHasPermission
// and Explain: perms that are either self-scope OR present in every role's
// ROLE_PERMISSIONS entry return true without consulting Helios or the
// cache. Critical for root-tenant users who have no Helios membership row.

// TestCallerHasPermission_SelfScope_ShortCircuits: a self-scope perm must
// return true even when Helios returns not_a_member, and must NOT populate
// the cache (the lookup never happens).
func TestCallerHasPermission_SelfScope_ShortCircuits(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	})
	defer f.close()
	c, cache := testClient(f.client(), nil)

	allowed, err := c.CallerHasPermission(
		context.Background(),
		"root-platform-admin",
		"root-tenant-uuid",
		hp.PermissionMercuryUserWriteSelf,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected self-scope perm to short-circuit to true")
	}
	if atomic.LoadInt32(&f.hits) != 0 {
		t.Fatalf("short-circuit must not hit Helios, got %d hits", f.hits)
	}
	if cached, _ := cache.Get("root-platform-admin", "root-tenant-uuid"); cached != nil {
		t.Fatalf("short-circuit must not populate cache, got %v", cached)
	}
}

// TestCallerHasPermission_UniversalByRole_ShortCircuits: mercury:api_keys:read
// is granted to all 4 roles (OWNER+ADMIN+EDITOR+VIEWER), so the SDK
// short-circuits without consulting Helios.
func TestCallerHasPermission_UniversalByRole_ShortCircuits(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)

	allowed, err := c.CallerHasPermission(
		context.Background(),
		"root-admin",
		"root-tenant",
		hp.PermissionMercuryApi_keysRead,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected universal-by-role perm to short-circuit to true")
	}
	if atomic.LoadInt32(&f.hits) != 0 {
		t.Fatalf("short-circuit must not hit Helios, got %d hits", f.hits)
	}
}

// TestCallerHasPermission_NonUniversal_ConsultsHelios: mercury:api_keys:create
// is OWNER+ADMIN only. A VIEWER's role does NOT grant it, so the SDK must
// consult Helios and deny.
func TestCallerHasPermission_NonUniversal_ConsultsHelios(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"active","role":"VIEWER","permissions":["mercury:api_keys:read"]}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)

	allowed, err := c.CallerHasPermission(
		context.Background(),
		"viewer",
		"t1",
		hp.PermissionMercuryApi_keysCreate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("VIEWER should not have api_keys:create")
	}
	if atomic.LoadInt32(&f.hits) != 1 {
		t.Fatalf("non-universal perm must consult Helios, got %d hits", f.hits)
	}
}

// TestExplain_UniversalPerm_DoesNotConsultHelios.
func TestExplain_UniversalPerm_DoesNotConsultHelios(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)

	exp, err := c.Explain(
		context.Background(),
		"root-admin",
		"root-tenant",
		hp.PermissionMercuryUserWriteSelf,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Allowed || exp.Reason != "granted_by_role" {
		t.Fatalf("unexpected explanation: %+v", exp)
	}
	if atomic.LoadInt32(&f.hits) != 0 {
		t.Fatalf("Explain of universal perm must not hit Helios, got %d hits", f.hits)
	}
}

// TestGetUserPermissions_FoldsSelfScope_ForRootTenantNotMember: a root-tenant
// user (Helios returns not_a_member) must still see the self-scope perms in
// the returned list — that's the whole point of foldSelfPermissions.
func TestGetUserPermissions_FoldsSelfScope_ForRootTenantNotMember(t *testing.T) {
	f := newHeliosFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"not_a_member"}`)
	})
	defer f.close()
	c, _ := testClient(f.client(), nil)

	got, err := c.GetUserPermissions(context.Background(), "root-admin", "root-tenant")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []hp.Permission{
		hp.PermissionMercuryUserReadSelf,
		hp.PermissionMercuryUserWriteSelf,
		hp.PermissionMercuryUserDeleteSelf,
	} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %s in folded perms, got: %v", want, got)
		}
	}
}
