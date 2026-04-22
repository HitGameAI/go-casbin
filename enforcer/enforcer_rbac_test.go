/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_rbac_test.go
 * @Description: 测试RBAC模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBACBasicEnforce(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should read data1 (direct policy)")

	ok, err = e.Enforce("alice", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should write data1 (direct policy)")

	ok, err = e.Enforce("alice", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice inherits admin role, should read data2")

	ok, err = e.Enforce("alice", "data2", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "alice inherits admin role, should write data2")

	ok, err = e.Enforce("bob", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "bob should read data2 (direct policy)")

	ok, err = e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "bob should not read data1")

	ok, err = e.Enforce("bob", "data1", "write")
	assert.NoError(t, err)
	assert.False(t, ok, "bob should not write data1")
}

func TestRBACGetRolesForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	roles := e.GetRolesForUser("alice")
	assert.Contains(t, roles, "admin", "alice should have admin role")

	roles = e.GetRolesForUser("bob")
	assert.Contains(t, roles, "viewer", "bob should have viewer role")

	roles = e.GetRolesForUser("nonexistent")
	assert.Empty(t, roles, "nonexistent user should have no roles")
}

func TestRBACGetUsersForRole(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	users := e.GetUsersForRole("admin")
	assert.Contains(t, users, "alice", "alice should be in admin role")

	users = e.GetUsersForRole("viewer")
	assert.Contains(t, users, "bob", "bob should be in viewer role")
}

func TestRBACHasRoleForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	assert.True(t, e.HasRoleForUser("alice", "admin"), "alice should have admin role")
	assert.False(t, e.HasRoleForUser("alice", "viewer"), "alice should not have viewer role")
	assert.True(t, e.HasRoleForUser("bob", "viewer"), "bob should have viewer role")
}

func TestRBACAddRoleForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.AddRoleForUser("bob", "admin")
	assert.NoError(t, err)

	assert.True(t, e.HasRoleForUser("bob", "admin"), "bob should now have admin role")

	ok, err := e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "bob with admin role should read data1")
}

func TestRBACDeleteRoleForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.DeleteRoleForUser("alice", "admin")
	assert.NoError(t, err)

	assert.False(t, e.HasRoleForUser("alice", "admin"), "alice should no longer have admin role")

	ok, err := e.Enforce("alice", "data2", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice without admin role should not read data2")
}

func TestRBACDeleteRolesForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.DeleteRolesForUser("alice")
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice")
	assert.Empty(t, roles, "alice should have no roles after DeleteRolesForUser")

	ok, err := e.Enforce("alice", "data2", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice without roles should not read data2")
}

func TestRBACDeleteUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.DeleteUser("alice")
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice")
	assert.Empty(t, roles, "alice should have no roles after DeleteUser")
}

func TestRBACDeleteRole(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.DeleteRole("admin")
	assert.NoError(t, err)

	users := e.GetUsersForRole("admin")
	assert.Empty(t, users, "admin role should have no users after deletion")
}

func TestRBACGetImplicitRoles(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	implicitRoles := e.GetImplicitRolesForUser("alice")
	assert.Contains(t, implicitRoles, "admin", "alice should have implicit admin role")
}

func TestRBACGetImplicitPermissions(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	perms := e.GetImplicitPermissionsForUser("alice")
	assert.NotEmpty(t, perms, "alice should have implicit permissions via admin role")

	found := false
	for _, p := range perms {
		if p[0] == "admin" && p[1] == "data2" && p[2] == "read" {
			found = true
		}
	}
	assert.True(t, found, "alice should inherit admin's data2 read permission")
}

func TestRBACGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.AddGroupingPolicy("bob", "admin")
	assert.NoError(t, err)

	assert.True(t, e.HasRoleForUser("bob", "admin"), "bob should have admin role after grouping")

	err = e.RemoveGroupingPolicy("bob", "admin")
	assert.NoError(t, err)

	assert.False(t, e.HasRoleForUser("bob", "admin"), "bob should not have admin role after removing grouping")
}

func TestRBACBatchGroupingPolicies(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	rules := [][]string{
		{"bob", "admin"},
		{"charlie", "viewer"},
	}
	err := e.AddGroupingPolicies(rules)
	assert.NoError(t, err)

	assert.True(t, e.HasRoleForUser("bob", "admin"))
	assert.True(t, e.HasRoleForUser("charlie", "viewer"))

	err = e.RemoveGroupingPolicies(rules)
	assert.NoError(t, err)

	assert.False(t, e.HasRoleForUser("bob", "admin"))
	assert.False(t, e.HasRoleForUser("charlie", "viewer"))
}

func TestRBACAddPermissionForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.AddPermissionForUser("bob", "data1", "read")
	assert.NoError(t, err)

	assert.True(t, e.HasPermissionForUser("bob", "data1", "read"))

	ok, err := e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRBACAddPermissionsForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.AddPermissionsForUser("bob", []string{"data1", "read"}, []string{"data1", "write"})
	assert.NoError(t, err)

	assert.True(t, e.HasPermissionForUser("bob", "data1", "read"))
	assert.True(t, e.HasPermissionForUser("bob", "data1", "write"))
}

func TestRBACDeletePermission(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.DeletePermission("data2", "read")
	assert.NoError(t, err)

	ok, err := e.Enforce("bob", "data2", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "nobody should read data2 after deleting the permission")
}

func TestRBACGetAllSubjects(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	subjects := e.GetAllSubjects()
	assert.NotEmpty(t, subjects)
}

func TestRBACGetAllRoles(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	roles := e.GetAllRoles()
	assert.NotEmpty(t, roles)
}

func TestRBACGetPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	policies := e.GetPolicy()
	assert.NotEmpty(t, policies, "should have policies loaded")
}

func TestRBACGetGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	grouping := e.GetGroupingPolicy()
	assert.NotEmpty(t, grouping, "should have grouping policies loaded")
}

func TestRBACHasPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	assert.True(t, e.HasPermissionForUser("alice", "data1", "read"))
	assert.False(t, e.HasPermissionForUser("alice", "data2", "write"))
}

func TestRBACHasGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	assert.True(t, e.HasGroupingPolicy("alice", "admin"))
	assert.False(t, e.HasGroupingPolicy("bob", "admin"))
}

func TestRBACGetFilteredPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	filtered := e.GetFilteredPolicy(0, "admin")
	assert.NotEmpty(t, filtered, "should have policies for admin")

	for _, p := range filtered {
		assert.Equal(t, "admin", p[0])
	}
}

func TestRBACEnforceEx(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	ok, matched, err := e.EnforceEx("alice", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotEmpty(t, matched, "should return matched policy")
}

func TestRBACBatchEnforce(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"alice", "data2", "read"},
		{"bob", "data1", "read"},
	}
	results, err := e.BatchEnforce(requests)
	assert.NoError(t, err)
	assert.Len(t, results, 3)
	assert.True(t, results[0])
	assert.True(t, results[1])
	assert.False(t, results[2])
}

func TestNewEnforcerWithModelText(t *testing.T) {
	modelText := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act`

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAutoSave(false),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	err = e.AddPolicy("alice", "data1", "read")
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestNewEnforcerNoModel(t *testing.T) {
	_, err := NewEnforcer()
	assert.Error(t, err, "should error when no model source provided")
}
