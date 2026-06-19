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

// TestRoleHasPermissionOwnerUniversal walks OWNER's perm set and
// asserts the universal perm is present plus the OWNER-only ones.
func TestRoleHasPermissionOwnerUniversal(t *testing.T) {
	if !hp.RoleHasPermission(hp.RoleOwner, hp.PermissionHeliosTenantSwitch) {
		t.Fatal("OWNER must have helios:tenant:switch (universal perm)")
	}
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

// TestRoleHasPermissionUniversalAcrossAllRoles — every role has
// helios:tenant:switch.
func TestRoleHasPermissionUniversalAcrossAllRoles(t *testing.T) {
	for _, r := range hp.Roles {
		if !hp.RoleHasPermission(r, hp.PermissionHeliosTenantSwitch) {
			t.Fatalf("role %s missing universal perm helios:tenant:switch", r)
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
