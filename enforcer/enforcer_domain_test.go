/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_domain_test.go
 * @Description: 测试域模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRBACDomainBasicEnforce(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	ok, err := e.Enforce("alice", "tenant1", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice as admin in tenant1 should read data1")

	ok, err = e.Enforce("alice", "tenant1", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "alice as admin in tenant1 should write data1")

	ok, err = e.Enforce("alice", "tenant2", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice as viewer in tenant2 should read data2")

	ok, err = e.Enforce("alice", "tenant2", "data2", "write")
	assert.NoError(t, err)
	assert.False(t, ok, "alice as viewer in tenant2 should not write data2")

	ok, err = e.Enforce("bob", "tenant1", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "bob as viewer in tenant1 should not read data1 (no policy)")

	ok, err = e.Enforce("bob", "tenant2", "data2", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "bob is not in tenant2, should not read data2")
}

func TestRBACDomainGetRolesInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	assert.Contains(t, roles, "admin", "alice should have admin role in tenant1")

	roles = e.GetRolesForUserInDomain("alice", "tenant2")
	assert.Contains(t, roles, "viewer", "alice should have viewer role in tenant2")

	roles = e.GetRolesForUserInDomain("bob", "tenant1")
	assert.Contains(t, roles, "viewer", "bob should have viewer role in tenant1")
}

func TestRBACDomainGetUsersInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	users := e.GetUsersForRoleInDomain("admin", "tenant1")
	assert.Contains(t, users, "alice", "alice should be admin in tenant1")

	users = e.GetUsersForRoleInDomain("viewer", "tenant2")
	assert.Contains(t, users, "alice", "alice should be viewer in tenant2")
}

func TestRBACDomainAddRoleInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.AddRoleForUserInDomain("bob", "admin", "tenant2")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("bob", "tenant2")
	assert.Contains(t, roles, "admin", "bob should have admin role in tenant2")
}

func TestRBACDomainDeleteRoleInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.DeleteRoleForUserInDomain("alice", "admin", "tenant1")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	assert.NotContains(t, roles, "admin", "alice should not have admin role in tenant1 after deletion")
}

func TestRBACDomainDeleteRolesForUserInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.DeleteRolesForUserInDomain("alice", "tenant1")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	assert.Empty(t, roles, "alice should have no roles in tenant1")

	roles = e.GetRolesForUserInDomain("alice", "tenant2")
	assert.NotEmpty(t, roles, "alice should still have roles in tenant2")
}

func TestRBACDomainGetPermissionsInDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	perms := e.GetPermissionsForUserInDomain("alice", "tenant1")
	assert.NotEmpty(t, perms, "alice should have permissions in tenant1 via admin role")
}

func TestRBACDomainGetAllDomains(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	domains := e.GetAllDomains()
	assert.NotEmpty(t, domains, "should have domains")
}

func TestRBACDomainDeleteAllUsersByDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.DeleteAllUsersByDomain("tenant1")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	assert.Empty(t, roles, "alice should have no roles in tenant1 after domain deletion")

	roles = e.GetRolesForUserInDomain("alice", "tenant2")
	assert.NotEmpty(t, roles, "alice should still have roles in tenant2")
}

func TestRBACDomainDeleteDomains(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.DeleteDomains("tenant1", "tenant2")
	assert.NoError(t, err)

	domains := e.GetAllDomains()
	assert.Empty(t, domains, "all domains should be deleted")
}

func TestRBACDomainGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.AddGroupingPolicy("charlie", "admin", "tenant1")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("charlie", "tenant1")
	assert.Contains(t, roles, "admin", "charlie should have admin role in tenant1")

	err = e.RemoveGroupingPolicy("charlie", "admin", "tenant1")
	assert.NoError(t, err)

	roles = e.GetRolesForUserInDomain("charlie", "tenant1")
	assert.NotContains(t, roles, "admin", "charlie should not have admin role after removal")
}

func TestRBACDomainFilteredGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	err := e.RemoveFilteredGroupingPolicy(2, "tenant1")
	assert.NoError(t, err)

	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	assert.Empty(t, roles, "all tenant1 roles should be removed")

	roles = e.GetRolesForUserInDomain("alice", "tenant2")
	assert.NotEmpty(t, roles, "tenant2 roles should remain")
}

func TestGetPermissionsInDomains(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	// alice 在 tenant1 是 admin，在 tenant2 是 viewer
	// admin 在 tenant1: data1:read, data1:write
	// viewer 在 tenant2: data2:read
	// alice 自身无直接 p 策略，权限全来自角色
	queries := []DomainQuery{
		{Subject: "admin", Domain: "tenant1"},
		{Subject: "viewer", Domain: "tenant2"},
	}
	perms := e.GetPermissionsInDomains(queries)
	assert.NotEmpty(t, perms, "should have permissions")
	assert.Contains(t, perms, "data1:read", "admin in tenant1 can read data1")
	assert.Contains(t, perms, "data1:write", "admin in tenant1 can write data1")
	assert.Contains(t, perms, "data2:read", "viewer in tenant2 can read data2")
	assert.NotContains(t, perms, "data2:write", "viewer in tenant2 cannot write data2")
}

func TestGetPermissionsInDomainsEmpty(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	perms := e.GetPermissionsInDomains(nil)
	assert.Nil(t, perms, "empty queries should return nil")
}

func TestGetPermissionsInDomainsNoMatch(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	queries := []DomainQuery{
		{Subject: "unknown_role", Domain: "tenant1"},
	}
	perms := e.GetPermissionsInDomains(queries)
	assert.Empty(t, perms, "no matching subject should return empty")
}

func TestGetPermissionsInDomainsDedup(t *testing.T) {
	e := newTestEnforcer(t, rbacDomainModelPath, rbacDomainPolicyPath)

	// admin 在 tenant1 和 tenant2 都有 data2:read（tenant2 的 admin 策略存在）
	// 重复查询同一 (subject, domain) 应去重
	queries := []DomainQuery{
		{Subject: "admin", Domain: "tenant1"},
		{Subject: "admin", Domain: "tenant2"},
		{Subject: "admin", Domain: "tenant1"}, // 重复
	}
	perms := e.GetPermissionsInDomains(queries)
	assert.NotEmpty(t, perms, "should have permissions")

	// 验证去重：结果中不应有重复项
	permSet := make(map[string]int)
	for _, p := range perms {
		permSet[p]++
	}
	for p, count := range permSet {
		assert.Equal(t, 1, count, "permission %q should appear only once", p)
	}
}
