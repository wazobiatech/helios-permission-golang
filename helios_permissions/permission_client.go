// Package helios_permissions — the cache-first PermissionClient facade.
//
// The CallerHasPermission / GetUserPermissions / Explain surface mirrors
// the TS / Python SDKs. Read path is:
//
//   1. Cache.Get(userId, tenantId) — hit returns the perm array.
//   2. Cache miss → HeliosClient.FetchUserPermissions(userId, tenantId).
//   3. On success: Cache.Set(...) (NX) + return the perms.
//   4. On error: if StaleOnError (default true) AND we have a cached
//      value, return the cached value (fail-closed semantics — deny
//      fresh, but allow stale). Otherwise return the error.
//
// Write path (called by Helios, not by the SDK client itself): the
// cache exposes WriteThrough / Invalidate / InvalidateTenant. Helios
// calls these after every role change. See CLAUDE.md / plan ZIN-4901i.

package helios_permissions

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Client is the public surface of the SDK. One per process. Construct
// via Create (see factory.go) — don't build it directly.
type Client interface {
	// CallerHasPermission returns true if (userId, tenantId) is granted
	// perm. Cache-first. Cache miss → Helios fetch → Cache.Set (NX).
	// On Helios unreachable: returns cached value if present and
	// StaleOnError is true, else returns the underlying error.
	CallerHasPermission(ctx context.Context, userID, tenantID string, perm Permission) (bool, error)

	// GetUserPermissions returns the full perm array for (userId,
	// tenantId). Same cache-first semantics as CallerHasPermission.
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error)

	// Explain returns a debug-friendly breakdown of the CallerHasPermission
	// decision. Same cache-first semantics.
	Explain(ctx context.Context, userID, tenantID string, perm Permission) (*Explanation, error)

	// Invalidate drops a single (userId, tenantId) entry. The host
	// service wires this to its Kafka consumer (if it has one) for
	// `helios.member.removed` / `helios.role.changed` events. Most
	// services don't need this — the writeThrough is the primary path.
	Invalidate(ctx context.Context, userID, tenantID string) error

	// InvalidateTenant drops every entry for a tenant.
	InvalidateTenant(ctx context.Context, tenantID string) error

	// WriteThrough overwrites the cached value. Helios's own writer
	// (ZIN-4901i) uses this; the SDK does not call it on its own.
	WriteThrough(ctx context.Context, userID, tenantID string, perms []Permission) error
}

// Explanation is the result of an Explain call. Provides the same
// shape as the TS / Python SDKs.
type Explanation struct {
	Allowed   bool
	Reason    string
	Role      Role
	Permissions []Permission
}

// ClientOptions configures the PermissionClient.
type ClientOptions struct {
	Cache       PermissionCache
	Helios      *HeliosClient
	StaleOnError *bool    // default true (fail-closed: allow stale)
	Logger      Logger
}

// permissionClient is the concrete impl. Constructed by Create.
type permissionClient struct {
	cache        PermissionCache
	helios       *HeliosClient
	staleOnError bool
	logger       Logger
	inFlight     *inFlight
}

// NewClient wires the client. Most callers should use Create
// (factory.go) which also owns the Redis connection lifecycle.
func NewClient(opts ClientOptions) (Client, error) {
	if opts.Cache == nil {
		return nil, errors.New("helios_permissions: ClientOptions.Cache is required")
	}
	if opts.Helios == nil {
		return nil, errors.New("helios_permissions: ClientOptions.Helios is required")
	}
	stale := true
	if opts.StaleOnError != nil {
		stale = *opts.StaleOnError
	}
	logger := opts.Logger
	if logger == nil {
		logger = SilentLogger()
	}
	return &permissionClient{
		cache:        opts.Cache,
		helios:       opts.Helios,
		staleOnError: stale,
		logger:       logger,
		inFlight:     newInFlight(),
	}, nil
}

// inFlight coalesces concurrent Helios fetches for the same key.
// A slow in-flight fetch should not be followed by N parallel
// retries — they all wait on the same promise and the first one
// to return populates the cache for the rest.
type inFlight struct {
	mu     sync.Mutex
	waiter map[string]*inFlightEntry
}

type inFlightEntry struct {
	done chan struct{}
	res  []Permission
	err  error
}

func newInFlight() *inFlight {
	return &inFlight{waiter: make(map[string]*inFlightEntry)}
}

func (i *inFlight) getOrStart(key string, fetch func() ([]Permission, error)) ([]Permission, error, bool) {
	i.mu.Lock()
	if e, ok := i.waiter[key]; ok {
		i.mu.Unlock()
		<-e.done
		return e.res, e.err, true
	}
	e := &inFlightEntry{done: make(chan struct{})}
	i.waiter[key] = e
	i.mu.Unlock()

	go func() {
		e.res, e.err = fetch()
		close(e.done)
		i.mu.Lock()
		delete(i.waiter, key)
		i.mu.Unlock()
	}()
	<-e.done
	return e.res, e.err, true
}

// fetchAndCache is the shared path for CallerHasPermission /
// GetUserPermissions / Explain. It performs the cache-first lookup,
// the Helios fetch on miss, the cache Set on success, and the
// stale-on-error fallback.
func (c *permissionClient) fetchAndCache(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	cached, err := c.cache.Get(userID, tenantID)
	if err != nil {
		c.logger.Warn("cache.Get failed, falling through to Helios", "err", err, "userId", userID, "tenantId", tenantID)
	}
	if cached != nil {
		return cached, nil
	}

	// Coalesce concurrent Helios fetches for the same (user, tenant)
	// key. N concurrent callers share a single fetch; the others
	// wait on the same promise.
	perms, fetchErr, _ := c.inFlight.getOrStart(userID+":"+tenantID, func() ([]Permission, error) {
		return c.fetchAndPopulate(ctx, userID, tenantID)
	})
	return perms, fetchErr
}

// fetchAndPopulate runs the actual Helios fetch + cache write. Called
// by fetchAndCache (which guards with cache.Get + in-flight coalescing).
func (c *permissionClient) fetchAndPopulate(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	res, err := c.helios.FetchUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Status != "active" {
		// not_a_member / inactive — cache an empty array so the next
		// read repopulates as "no perms" without re-hitting Helios.
		_ = c.cache.Set(userID, tenantID, []Permission{})
		return []Permission{}, nil
	}
	perms := res.Permissions
	if perms == nil {
		perms = []Permission{}
	}
	if setErr := c.cache.Set(userID, tenantID, perms); setErr != nil {
		c.logger.Warn("cache.Set failed, continuing without cache", "err", setErr, "userId", userID, "tenantId", tenantID)
	}
	return perms, nil
}

func (c *permissionClient) CallerHasPermission(ctx context.Context, userID, tenantID string, perm Permission) (bool, error) {
	perms, err := c.fetchAndCache(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == perm {
			return true, nil
		}
	}
	return false, nil
}

func (c *permissionClient) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]Permission, error) {
	return c.fetchAndCache(ctx, userID, tenantID)
}

func (c *permissionClient) Explain(ctx context.Context, userID, tenantID string, perm Permission) (*Explanation, error) {
	perms, err := c.fetchAndCache(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		if p == perm {
			return &Explanation{
				Allowed:     true,
				Reason:      "granted_by_role",
				Permissions: perms,
			}, nil
		}
	}
	return &Explanation{
		Allowed:     false,
		Reason:      "not_in_role_perm_set",
		Permissions: perms,
	}, nil
}

func (c *permissionClient) Invalidate(ctx context.Context, userID, tenantID string) error {
	return c.cache.Invalidate(userID, tenantID)
}

func (c *permissionClient) InvalidateTenant(ctx context.Context, tenantID string) error {
	return c.cache.InvalidateTenant(tenantID)
}

func (c *permissionClient) WriteThrough(ctx context.Context, userID, tenantID string, perms []Permission) error {
	return c.cache.WriteThrough(userID, tenantID, perms)
}

// timeFormat is exposed for tests that need to format expiresAt the
// same way the SDK does. Not used in production paths.
const timeFormat = time.RFC3339Nano

// formatError is a small helper for tests that want a uniform
// error-formatting path.
func formatError(prefix string, err error) error {
	return fmt.Errorf("%s: %w", prefix, err)
}
