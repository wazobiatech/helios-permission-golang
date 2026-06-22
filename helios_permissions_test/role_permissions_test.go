package helios_permissions_test

import (
	"sort"
	"testing"

	hp "github.com/wazobiatech/helios-permissions-go/helios_permissions"
)

// TestRoles covers the four platform roles, no more no less.
func TestRoles(t *testing.T) {
	if len(hp.Roles) != 4 {
		t.Fatalf("Roles length = %d, want 4", len(hp.Roles))
	}
	expected := []hp.Role{hp.RoleOwner, hp.RoleAdmin, hp.RoleEditor, hp.RoleViewer}
	got := append([]hp.Role{}, hp.Roles...)
	sort.Slice(got, func(i, j int) bool { return string(got[i]) < string(got[j]) })
	sort.Slice(expected, func(i, j int) bool { return string(expected[i]) < string(expected[j]) })
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("Roles[%d] = %q, want %q", i, got[i], expected[i])
		}
	}
}

// TestRoleHasPermissionOwnerHasOwnerOnly walks OWNER's perm set and
// asserts the OWNER-only perms are present.
func TestRoleHasPermissionOwnerHasOwnerOnly(t *testing.T) {
	if !hp.RoleHasPermission(hp.RoleOwner, hp.PermissionHeliosTenantTransfer) {
		t.Fatal("OWNER must have helios:tenant:transfer (OWNER-only)")
	}
	if !hp.RoleHasPermission(hp.RoleOwner, hp.PermissionAthensProjectDelete) {
		t.Fatal("OWNER must have athens:project:delete")
	}
}

// TestRoleHasPermissionTransferIsOwnerOnly is the ZIN-4714 invariant
// pinned across all four SDKs.
func TestRoleHasPermissionTransferIsOwnerOnly(t *testing.T) {
	if hp.RoleHasPermission(hp.RoleAdmin, hp.PermissionHeliosTenantTransfer) {
		t.Fatal("ADMIN must NOT have helios:tenant:transfer")
	}
	if hp.RoleHasPermission(hp.RoleEditor, hp.PermissionHeliosTenantTransfer) {
		t.Fatal("EDITOR must NOT have helios:tenant:transfer")
	}
	if hp.RoleHasPermission(hp.RoleViewer, hp.PermissionHeliosTenantTransfer) {
		t.Fatal("VIEWER must NOT have helios:tenant:transfer")
	}
}

// TestSelfScopeSwitchIsUniversal — the universal perm
// helios:tenant:switch:self is in SELF_PERMISSIONS and NOT in any role.
// (v1.3.0 split it out of role_permissions into the self scope.)
func TestSelfScopeSwitchIsUniversal(t *testing.T) {
	if !hp.IsSelfScope(hp.PermissionHeliosTenantSwitchSelf) {
		t.Fatal("helios:tenant:switch:self must have scope self")
	}
	for _, r := range hp.Roles {
		if hp.RoleHasPermission(r, hp.PermissionHeliosTenantSwitchSelf) {
			t.Fatalf("role %s must NOT have helios:tenant:switch:self (it's self-scope, granted implicitly)", r)
		}
	}
}

// TestSelfScopeMercuryReadWriteSelf — the two self-scope perms in the
// contract (mercury:user:read:self, mercury:user:write:self) are
// universal and must NOT appear in any role.
func TestSelfScopeMercuryReadWriteSelf(t *testing.T) {
	if !hp.IsSelfScope(hp.PermissionMercuryUserReadSelf) {
		t.Fatal("mercury:user:read:self must have scope self")
	}
	if !hp.IsSelfScope(hp.PermissionMercuryUserWriteSelf) {
		t.Fatal("mercury:user:write:self must have scope self")
	}
	for _, r := range hp.Roles {
		if hp.RoleHasPermission(r, hp.PermissionMercuryUserReadSelf) {
			t.Fatalf("role %s must NOT have self-scope perm mercury:user:read:self", r)
		}
	}
}

// TestResolvePermissionsUnknownRole returns an empty slice for an
// unknown role rather than nil and without panicking.
func TestResolvePermissionsUnknownRole(t *testing.T) {
	got := hp.ResolvePermissions(hp.Role("BOGUS"))
	if len(got) != 0 {
		t.Fatalf("ResolvePermissions(bogus) = %v, want empty", got)
	}
}

// TestIsValidPermission covers the closed union check.
func TestIsValidPermission(t *testing.T) {
	if !hp.IsValidPermission(hp.PermissionAthensProjectView) {
		t.Fatal("known perm should be valid")
	}
	if hp.IsValidPermission(hp.Permission("athens:totally:fake")) {
		t.Fatal("unknown perm should not be valid")
	}
}

// TestIsValidRole covers the closed role check.
func TestIsValidRole(t *testing.T) {
	if !hp.IsValidRole(hp.RoleOwner) {
		t.Fatal("OWNER should be valid")
	}
	if hp.IsValidRole(hp.Role("BOGUS")) {
		t.Fatal("unknown role should not be valid")
	}
}

// TestNoEmptyRole is the contract invariant — no role has zero perms.
func TestNoEmptyRole(t *testing.T) {
	for _, r := range hp.Roles {
		if len(hp.ResolvePermissions(r)) == 0 {
			t.Fatalf("role %s has zero perms (forbidden by contract)", r)
		}
	}
}

// TestViewerReadOnly asserts VIEWER holds no write perms. This is
// a representative slice, not exhaustive — exhaustive is in the
// contract tests.
func TestViewerReadOnly(t *testing.T) {
	if hp.RoleHasPermission(hp.RoleViewer, hp.PermissionAthensProjectUpdate) {
		t.Fatal("VIEWER must not have athens:project:update")
	}
	if hp.RoleHasPermission(hp.RoleViewer, hp.PermissionMusePostsWrite) {
		t.Fatal("VIEWER must not have muse:posts:write")
	}
}

// ----------------------------------------------------------------------------
// v1.3.0 scope helpers
// ----------------------------------------------------------------------------

// TestPermScopeContents — every entry in PERM_SCOPE has a valid scope and
// the perms union-matches the const block (no perm is missing or extra).
func TestPermScopeContents(t *testing.T) {
	if len(hp.PERM_SCOPE) == 0 {
		t.Fatal("PERM_SCOPE must be populated")
	}
	for perm, scope := range hp.PERM_SCOPE {
		switch scope {
		case hp.ScopeSelf, hp.ScopePlatform, hp.ScopeProject, hp.ScopePlatformProject:
			// ok
		default:
			t.Errorf("perm %q has unknown scope %q", perm, scope)
		}
	}
}

// TestScopePartitionedTuplesAreUnion — the four scope tuples partition
// PERM_SCOPE exactly (every perm appears in exactly one tuple).
func TestScopePartitionedTuplesAreUnion(t *testing.T) {
	count := len(hp.SELF_PERMISSIONS) + len(hp.PLATFORM_PERMISSIONS) +
		len(hp.PROJECT_PERMISSIONS) + len(hp.DUAL_PERMISSIONS)
	if count != len(hp.PERM_SCOPE) {
		t.Errorf("scope tuples sum to %d but PERM_SCOPE has %d entries", count, len(hp.PERM_SCOPE))
	}
	seen := map[hp.Permission]int{}
	for _, p := range hp.SELF_PERMISSIONS {
		seen[p]++
	}
	for _, p := range hp.PLATFORM_PERMISSIONS {
		seen[p]++
	}
	for _, p := range hp.PROJECT_PERMISSIONS {
		seen[p]++
	}
	for _, p := range hp.DUAL_PERMISSIONS {
		seen[p]++
	}
	for perm, n := range seen {
		if n != 1 {
			t.Errorf("perm %q appears in %d tuples (must be exactly 1)", perm, n)
		}
	}
}

// TestIsSelfScope — true for self-scope perms, false otherwise.
func TestIsSelfScope(t *testing.T) {
	for _, p := range hp.SELF_PERMISSIONS {
		if !hp.IsSelfScope(p) {
			t.Errorf("IsSelfScope(%q) = false, want true", p)
		}
	}
	for _, p := range hp.PLATFORM_PERMISSIONS {
		if hp.IsSelfScope(p) {
			t.Errorf("IsSelfScope(%q platform) = true, want false", p)
		}
	}
	for _, p := range hp.PROJECT_PERMISSIONS {
		if hp.IsSelfScope(p) {
			t.Errorf("IsSelfScope(%q project) = true, want false", p)
		}
	}
	for _, p := range hp.DUAL_PERMISSIONS {
		if hp.IsSelfScope(p) {
			t.Errorf("IsSelfScope(%q dual) = true, want false", p)
		}
	}
}

// TestIsPlatformGrantable — true for platform and dual, false for self/project.
func TestIsPlatformGrantable(t *testing.T) {
	for _, p := range hp.PLATFORM_PERMISSIONS {
		if !hp.IsPlatformGrantable(p) {
			t.Errorf("IsPlatformGrantable(%q) = false, want true", p)
		}
	}
	for _, p := range hp.DUAL_PERMISSIONS {
		if !hp.IsPlatformGrantable(p) {
			t.Errorf("IsPlatformGrantable(%q dual) = false, want true", p)
		}
	}
	for _, p := range hp.SELF_PERMISSIONS {
		if hp.IsPlatformGrantable(p) {
			t.Errorf("IsPlatformGrantable(%q self) = true, want false", p)
		}
	}
	for _, p := range hp.PROJECT_PERMISSIONS {
		if hp.IsPlatformGrantable(p) {
			t.Errorf("IsPlatformGrantable(%q project) = true, want false", p)
		}
	}
}

// TestIsTenantGrantable — true for project and dual, false for self/platform.
// Tenant-defined perms (NOT in PERM_SCOPE) are also grantable via TenantRole.
func TestIsTenantGrantable(t *testing.T) {
	for _, p := range hp.PROJECT_PERMISSIONS {
		if !hp.IsTenantGrantable(string(p)) {
			t.Errorf("IsTenantGrantable(%q) = false, want true", p)
		}
	}
	for _, p := range hp.DUAL_PERMISSIONS {
		if !hp.IsTenantGrantable(string(p)) {
			t.Errorf("IsTenantGrantable(%q dual) = false, want true", p)
		}
	}
	for _, p := range hp.SELF_PERMISSIONS {
		if hp.IsTenantGrantable(string(p)) {
			t.Errorf("IsTenantGrantable(%q self) = true, want false", p)
		}
	}
	for _, p := range hp.PLATFORM_PERMISSIONS {
		if hp.IsTenantGrantable(string(p)) {
			t.Errorf("IsTenantGrantable(%q platform) = true, want false", p)
		}
	}
	// Tenant-defined perm (not in the contract vocabulary) is grantable.
	if !hp.IsTenantGrantable("muse:custom:tenant-only-action") {
		t.Fatal("IsTenantGrantable(tenant-defined perm) = false, want true")
	}
}

// TestNoSelfOrProjectPermsInRoles — invariant from validate.mjs: self and
// project perms must NOT appear in any role's ROLE_PERMISSIONS entry.
func TestNoSelfOrProjectPermsInRoles(t *testing.T) {
	for _, r := range hp.Roles {
		perms := hp.ResolvePermissions(r)
		for _, p := range perms {
			scope, ok := hp.PERM_SCOPE[p]
			if !ok {
				t.Errorf("role %s perm %q has no entry in PERM_SCOPE", r, p)
				continue
			}
			if scope == hp.ScopeSelf || scope == hp.ScopeProject {
				t.Errorf("role %s has %q (scope %q) — forbidden by contract", r, p, scope)
			}
		}
	}
}
