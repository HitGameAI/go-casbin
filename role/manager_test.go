/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\manager_test.go
 * @Description: 角色管理器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

import (
	"testing"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager() *RoleManager {
	return NewRoleManager(logger.NewLogger())
}

func TestNewRoleManager(t *testing.T) {
	rm := newTestManager()
	assert.NotNil(t, rm)
}

func TestRoleManager_AddLink(t *testing.T) {
	rm := newTestManager()
	err := rm.AddLink("alice", "admin")
	require.NoError(t, err)
	assert.True(t, rm.HasLink("alice", "admin"))
}

func TestRoleManager_AddLink_WithDomain(t *testing.T) {
	rm := newTestManager()
	err := rm.AddLink("alice", "admin", "tenant1")
	require.NoError(t, err)

	assert.True(t, rm.HasLink("alice", "admin", "tenant1"))
	assert.False(t, rm.HasLink("alice", "admin", "tenant2"))
	assert.False(t, rm.HasLink("alice", "admin"))
}

func TestRoleManager_DeleteLink(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")

	rm.DeleteLink("alice", "admin")
	assert.False(t, rm.HasLink("alice", "admin"))
}

func TestRoleManager_HasLink_CacheHit(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")

	result1 := rm.HasLink("alice", "admin")
	assert.True(t, result1)

	result2 := rm.HasLink("alice", "admin")
	assert.True(t, result2)
}

func TestRoleManager_GetRoles(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("alice", "editor")

	roles := rm.GetRoles("alice")
	assert.Len(t, roles, 2)
}

func TestRoleManager_GetRoles_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")

	roles := rm.GetRoles("alice", "tenant1")
	assert.Contains(t, roles, "admin")
}

func TestRoleManager_GetUsers(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("bob", "admin")

	users := rm.GetUsers("admin")
	assert.Len(t, users, 2)
}

func TestRoleManager_GetImplicitRoles(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("admin", "editor")
	_ = rm.AddLink("editor", "viewer")

	roles := rm.GetImplicitRoles("alice")
	assert.Len(t, roles, 3) // admin, editor, viewer
}

func TestRoleManager_GetImplicitRoles_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("admin", "editor", "tenant1")

	roles := rm.GetImplicitRoles("alice", "tenant1")
	assert.Len(t, roles, 2)
}

func TestRoleManager_GetImplicitUsers(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("bob", "editor")
	_ = rm.AddLink("editor", "admin")

	users := rm.GetImplicitUsers("admin")
	assert.Contains(t, users, "alice")
	assert.Contains(t, users, "editor")
}

func TestRoleManager_GetDomains(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("alice", "editor", "tenant2")

	domains := rm.GetDomains("alice")
	assert.Len(t, domains, 2)
}

func TestRoleManager_DeleteDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("bob", "editor", "tenant2")

	rm.DeleteDomain("tenant1")
	assert.False(t, rm.HasLink("alice", "admin", "tenant1"))
	assert.True(t, rm.HasLink("bob", "editor", "tenant2"))
}

func TestRoleManager_Clear(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")

	rm.Clear()
	assert.False(t, rm.HasLink("alice", "admin"))
}

func TestRoleManager_SetMaxDepth(t *testing.T) {
	rm := newTestManager()
	rm.SetMaxDepth(2)

	_ = rm.AddLink("a", "b")
	_ = rm.AddLink("b", "c")
	_ = rm.AddLink("c", "d")

	roles := rm.GetImplicitRoles("a")
	assert.Len(t, roles, 2) // b, c
}

func TestRoleManager_GetHierarchy(t *testing.T) {
	rm := newTestManager()
	h := rm.GetHierarchy()
	assert.NotNil(t, h)
}

func TestRoleManager_CycleDetection(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("admin", "editor")
	err := rm.AddLink("editor", "admin")
	assert.Error(t, err)
}

func TestRoleManager_GetAllDomains(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("bob", "editor", "tenant2")

	domains := rm.GetAllDomains()
	assert.Len(t, domains, 2)
	assert.Contains(t, domains, "tenant1")
	assert.Contains(t, domains, "tenant2")
}

func TestRoleManager_GetAllDomains_NoDomains(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")

	domains := rm.GetAllDomains()
	assert.Empty(t, domains)
}

func TestRoleManager_DeleteDomain_CacheInvalidation(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("bob", "editor", "tenant2")

	// 先查询建立缓存
	assert.True(t, rm.HasLink("alice", "admin", "tenant1"))
	assert.True(t, rm.HasLink("bob", "editor", "tenant2"))

	// 删除域后缓存应失效
	rm.DeleteDomain("tenant1")
	assert.False(t, rm.HasLink("alice", "admin", "tenant1"))
	assert.True(t, rm.HasLink("bob", "editor", "tenant2"))
}

func TestRoleManager_Clear_WithCache(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("bob", "editor")

	// 先查询建立缓存
	assert.True(t, rm.HasLink("alice", "admin"))
	assert.True(t, rm.HasLink("bob", "editor"))

	// 清空后缓存应失效
	rm.Clear()
	assert.False(t, rm.HasLink("alice", "admin"))
	assert.False(t, rm.HasLink("bob", "editor"))
}

func TestRoleManager_InvalidateCache_OnAddLink(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")

	// 查询建立缓存
	assert.True(t, rm.HasLink("alice", "admin"))

	// 添加新链接后，缓存应失效，新的继承关系应可见
	_ = rm.AddLink("admin", "editor")
	assert.True(t, rm.HasLink("alice", "editor"))
}

func TestRoleManager_InvalidateCache_OnDeleteLink(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("admin", "editor")

	// 查询建立缓存
	assert.True(t, rm.HasLink("alice", "editor"))

	// 删除直接链接后，直接继承关系的缓存应失效
	rm.DeleteLink("alice", "admin")
	assert.False(t, rm.HasLink("alice", "admin"))
}

func TestRoleManager_InvalidateCache_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")

	// 查询建立缓存
	assert.True(t, rm.HasLink("alice", "admin", "tenant1"))

	// 添加新链接后缓存应失效
	_ = rm.AddLink("admin", "editor", "tenant1")
	assert.True(t, rm.HasLink("alice", "editor", "tenant1"))
}

func TestRoleManager_GetUsers_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("bob", "admin", "tenant1")

	users := rm.GetUsers("admin", "tenant1")
	assert.Len(t, users, 2)
}

func TestRoleManager_GetImplicitUsers_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")
	_ = rm.AddLink("bob", "editor", "tenant1")
	_ = rm.AddLink("editor", "admin", "tenant1")

	users := rm.GetImplicitUsers("admin", "tenant1")
	assert.Contains(t, users, "alice")
	assert.Contains(t, users, "editor")
}

func TestRoleManager_DeleteLink_WithDomain(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin", "tenant1")

	rm.DeleteLink("alice", "admin", "tenant1")
	assert.False(t, rm.HasLink("alice", "admin", "tenant1"))
}

func TestRoleManager_HasLink_NoInheritance(t *testing.T) {
	rm := newTestManager()
	_ = rm.AddLink("alice", "admin")
	assert.False(t, rm.HasLink("alice", "editor"))
}

func TestRoleManager_GetRoles_NoRoles(t *testing.T) {
	rm := newTestManager()
	roles := rm.GetRoles("alice")
	assert.Empty(t, roles)
}

func TestRoleManager_GetUsers_NoUsers(t *testing.T) {
	rm := newTestManager()
	users := rm.GetUsers("admin")
	assert.Empty(t, users)
}

func TestRoleManager_GetImplicitUsers_MaxDepth(t *testing.T) {
	rm := newTestManager()
	rm.SetMaxDepth(1)
	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("admin", "editor")
	_ = rm.AddLink("editor", "viewer")

	// maxDepth=1 时，只递归一层
	users := rm.GetImplicitUsers("viewer")
	assert.Contains(t, users, "editor")
	assert.NotContains(t, users, "admin")
}

func TestRoleManager_HasLink_Self(t *testing.T) {
	rm := newTestManager()
	// name1 == name2 时直接返回 true（自链接快速路径）
	assert.True(t, rm.HasLink("alice", "alice"))
	assert.True(t, rm.HasLink("alice", "alice", "tenant1"))
}
