/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_transaction_test.go
 * @Description: 测试事务模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransactionalSyncUserRoles(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddGroupingPolicy("alice", "admin")
	require.NoError(t, err)
	err = e.AddGroupingPolicy("bob", "viewer")
	require.NoError(t, err)

	assert.True(t, e.HasRoleForUser("alice", "admin"))
	assert.True(t, e.HasRoleForUser("bob", "viewer"))

	groupingRules := [][]string{
		{"alice", "viewer"},
		{"bob", "admin"},
	}
	err = e.TransactionalSyncUserRoles(context.Background(), "alice", groupingRules)
	assert.NoError(t, err)

	assert.True(t, e.HasRoleForUser("alice", "viewer"), "alice should now have viewer role")
	assert.False(t, e.HasRoleForUser("alice", "admin"), "alice should no longer have admin role")
	assert.True(t, e.HasRoleForUser("bob", "admin"), "bob should now have admin role")
}

func TestTransactionalSyncUserRolesEmpty(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddGroupingPolicy("alice", "admin")
	require.NoError(t, err)

	err = e.TransactionalSyncUserRoles(context.Background(), "alice", nil)
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice")
	assert.Empty(t, roles, "alice should have no roles after syncing with empty rules")
}

func TestTransactionalSyncUserRolesWithDomain(t *testing.T) {
	e := newMemoryEnforcer(t, rbacDomainModelPath)

	err := e.AddGroupingPolicy("alice", "admin", "tenant1")
	require.NoError(t, err)

	groupingRules := [][]string{
		{"alice", "viewer", "tenant2"},
	}
	err = e.TransactionalSyncUserRoles(context.Background(), "alice", groupingRules)
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice", "tenant2")
	assert.Contains(t, roles, "viewer", "alice should have viewer role in tenant2")

	roles = e.GetRolesForUser("alice", "tenant1")
	assert.Empty(t, roles, "alice should have no roles in tenant1 after sync")
}

func TestTransactionalDeleteUser(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)
	err = e.AddGroupingPolicy("alice", "admin")
	require.NoError(t, err)

	assert.True(t, e.HasPermissionForUser("alice", "data1", "read"))
	assert.True(t, e.HasRoleForUser("alice", "admin"))

	err = e.TransactionalDeleteUser(context.Background(), "alice")
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice")
	assert.Empty(t, roles, "alice should have no roles after transactional delete")
}

func TestTransactionalDeleteRole(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("admin", "data1", "read")
	require.NoError(t, err)
	err = e.AddGroupingPolicy("alice", "admin")
	require.NoError(t, err)

	assert.True(t, e.HasRoleForUser("alice", "admin"))

	err = e.TransactionalDeleteRole(context.Background(), "admin")
	assert.NoError(t, err)

	users := e.GetUsersForRole("admin")
	assert.Empty(t, users, "admin role should have no users after deletion")
}

func TestExecuteInTransaction(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	executed := false
	err := e.ExecuteInTransaction(context.Background(), func() error {
		executed = true
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, executed, "function should have been executed")
}

func TestExecuteInTransactionError(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.ExecuteInTransaction(context.Background(), func() error {
		return assert.AnError
	})
	assert.Error(t, err, "should propagate error from function")
}

func TestClearAllPolicies(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	policies := e.GetPolicy()
	assert.NotEmpty(t, policies, "should have policies before clear")

	err := e.ClearAllPolicies()
	assert.NoError(t, err)

	policies = e.GetPolicy()
	assert.Empty(t, policies, "should have no policies after clear")

	grouping := e.GetGroupingPolicy()
	assert.Empty(t, grouping, "should have no grouping policies after clear")
}

func TestDeleteRoleAssignments(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	assert.True(t, e.HasRoleForUser("alice", "admin"))

	err := e.DeleteRoleAssignments("admin")
	assert.NoError(t, err)

	users := e.GetUsersForRole("admin")
	assert.Empty(t, users, "admin should have no users after deleting assignments")
}
