// Package helios_permissions — cache abstraction.
//
// Two implementations:
//
//   InMemoryPermissionCache  — process-local. Tests + single-instance dev.
//   RedisPermissionCache     — go-redis client. Production. Reads the same
//                              `helios:perms:{userId}:{tenantId}` key shape
//                              that Helios writes via its writeThrough
//                              (see helios/src/internal/permission-cache.service.ts).
//
// The interface is the same; callers depend on the interface, the factory
// wires the impl.
package helios_permissions

// PermissionCache is the read/write surface for cached permission
// resolutions. Implementations are best-effort — a nil return from Get
// means "miss, fall through to Helios". WriteThrough / Invalidate
// failures are logged and swallowed (see implementation comments).
type PermissionCache interface {
	// Get returns the cached permission array for (userId, tenantId), or
	// nil on a miss. A nil with no error means "caller should hit Helios".
	Get(userID, tenantID string) ([]Permission, error)

	// Set stores perms for (userId, tenantId) with NX semantics — only
	// sets if the key is not present. Used by the in-flight read path
	// to repopulate after a Helios fetch.
	Set(userID, tenantID string, perms []Permission) error

	// WriteThrough overwrites the cached value for (userId, tenantId)
	// with the supplied perms. Used by Helios itself after a role change
	// to push the new authoritative value to every downstream SDK.
	// No NX — explicit overwrite.
	WriteThrough(userID, tenantID string, perms []Permission) error

	// Invalidate drops the (userId, tenantId) entry. Used after
	// removeMember / revokeInvitation.
	Invalidate(userID, tenantID string) error

	// InvalidateTenant drops every entry for a tenant. Used by destructive
	// tenant operations (disable_service, future tenant delete).
	InvalidateTenant(tenantID string) error
}
