package helios_permissions

import "sync"

// InMemoryPermissionCache is a process-local implementation of
// PermissionCache. Use for tests and single-instance dev. Production
// uses RedisPermissionCache (see factory.go).
//
// Concurrency: protected by a sync.RWMutex. Reads are common (every
// check call), writes are rare (cache miss repopulate + writeThrough
// from Helios).
type InMemoryPermissionCache struct {
	mu    sync.RWMutex
	store map[string][]Permission
}

// NewInMemoryPermissionCache returns an empty cache.
func NewInMemoryPermissionCache() *InMemoryPermissionCache {
	return &InMemoryPermissionCache{
		store: make(map[string][]Permission),
	}
}

func memKey(userID, tenantID string) string {
	return userID + ":" + tenantID
}

// Get returns the cached value, or nil on miss.
func (c *InMemoryPermissionCache) Get(userID, tenantID string) ([]Permission, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	perms, ok := c.store[memKey(userID, tenantID)]
	if !ok {
		return nil, nil
	}
	// Return a defensive copy so callers can't mutate the shared map.
	out := make([]Permission, len(perms))
	copy(out, perms)
	return out, nil
}

// Set stores perms with NX semantics. Returns true if the value was
// stored, false if the key was already present.
func (c *InMemoryPermissionCache) Set(userID, tenantID string, perms []Permission) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := memKey(userID, tenantID)
	if _, exists := c.store[k]; exists {
		return nil
	}
	c.store[k] = append([]Permission{}, perms...)
	return nil
}

// WriteThrough overwrites the cached value.
func (c *InMemoryPermissionCache) WriteThrough(userID, tenantID string, perms []Permission) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[memKey(userID, tenantID)] = append([]Permission{}, perms...)
	return nil
}

// Invalidate drops the (userId, tenantId) entry.
func (c *InMemoryPermissionCache) Invalidate(userID, tenantID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, memKey(userID, tenantID))
	return nil
}

// InvalidateTenant drops every entry for a tenant. Linear scan — fine
// for the in-memory store's typical size (a few hundred entries per
// process).
func (c *InMemoryPermissionCache) InvalidateTenant(tenantID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.store {
		// Key format is userID:tenantID — match the suffix.
		if endsWith(k, ":"+tenantID) {
			delete(c.store, k)
		}
	}
	return nil
}

func endsWith(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
