/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\hierarchy_test.go
 * @Description: 角色层级测试
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

func newTestHierarchy() *RoleHierarchy {
	return NewRoleHierarchy(logger.NewLogger())
}

func TestNewRoleHierarchy(t *testing.T) {
	rh := newTestHierarchy()
	assert.NotNil(t, rh)
}

func TestRoleHierarchy_AddLink(t *testing.T) {
	rh := newTestHierarchy()
	err := rh.AddLink("alice", "admin")
	require.NoError(t, err)
	assert.True(t, rh.HasLink("alice", "admin"))
}

func TestRoleHierarchy_AddLink_CycleDetection(t *testing.T) {
	rh := newTestHierarchy()
	err := rh.AddLink("admin", "editor")
	require.NoError(t, err)

	err = rh.AddLink("editor", "admin")
	assert.Error(t, err)
}

func TestRoleHierarchy_AddLink_SelfLoop(t *testing.T) {
	rh := newTestHierarchy()
	err := rh.AddLink("admin", "admin")
	assert.Error(t, err)
}

func TestRoleHierarchy_DeleteLink(t *testing.T) {
	rh := newTestHierarchy()
	err := rh.AddLink("alice", "admin")
	require.NoError(t, err)

	rh.DeleteLink("alice", "admin")
	assert.False(t, rh.HasLink("alice", "admin"))
}

func TestRoleHierarchy_DeleteLink_NonExistent(t *testing.T) {
	rh := newTestHierarchy()
	rh.DeleteLink("alice", "admin") // 不 panic
}

func TestRoleHierarchy_HasLink_Self(t *testing.T) {
	rh := newTestHierarchy()
	assert.True(t, rh.HasLink("alice", "alice"))
}

func TestRoleHierarchy_HasLink_Indirect(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")
	_ = rh.AddLink("admin", "editor")

	assert.True(t, rh.HasLink("alice", "editor"))
	assert.False(t, rh.HasLink("editor", "alice"))
}

func TestRoleHierarchy_GetRoles(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")
	_ = rh.AddLink("alice", "editor")

	roles := rh.GetRoles("alice")
	assert.Len(t, roles, 2)
}

func TestRoleHierarchy_GetRoles_NotFound(t *testing.T) {
	rh := newTestHierarchy()
	assert.Nil(t, rh.GetRoles("nonexistent"))
}

func TestRoleHierarchy_GetUsers(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")
	_ = rh.AddLink("bob", "admin")

	users := rh.GetUsers("admin")
	assert.Len(t, users, 2)
}

func TestRoleHierarchy_GetDomains(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("tenant1:alice", "tenant1:admin")
	_ = rh.AddLink("tenant2:alice", "tenant2:editor")

	domains := rh.GetDomains("alice")
	assert.Len(t, domains, 2)
}

func TestRoleHierarchy_GetAllDomains(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("tenant1:alice", "tenant1:admin")
	_ = rh.AddLink("tenant2:bob", "tenant2:editor")

	domains := rh.GetAllDomains()
	assert.Len(t, domains, 2)
}

func TestRoleHierarchy_DeleteDomain(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("tenant1:alice", "tenant1:admin")
	_ = rh.AddLink("tenant2:bob", "tenant2:editor")

	rh.DeleteDomain("tenant1")
	assert.False(t, rh.HasLink("tenant1:alice", "tenant1:admin"))
	assert.True(t, rh.HasLink("tenant2:bob", "tenant2:editor"))
}

func TestRoleHierarchy_DeleteDomain_CrossDomainLinks(t *testing.T) {
	rh := newTestHierarchy()
	// 域内角色继承域外角色
	_ = rh.AddLink("tenant1:alice", "global_admin")
	// 域外角色继承域内角色
	_ = rh.AddLink("bob", "tenant1:editor")

	rh.DeleteDomain("tenant1")

	// 域内角色节点被删除
	assert.False(t, rh.HasLink("tenant1:alice", "tenant1:admin"))
	// 域外角色对域内角色的链接被清理
	assert.False(t, rh.HasLink("bob", "tenant1:editor"))
	// 域外角色自身仍存在
	assert.True(t, rh.HasLink("global_admin", "global_admin"))
}

func TestRoleHierarchy_DeleteDomain_OnlyInDomainLinks(t *testing.T) {
	rh := newTestHierarchy()
	// 域内角色只继承域内角色
	_ = rh.AddLink("tenant1:alice", "tenant1:admin")
	_ = rh.AddLink("tenant1:admin", "tenant1:editor")

	rh.DeleteDomain("tenant1")
	assert.False(t, rh.HasLink("tenant1:alice", "tenant1:admin"))
}

func TestRoleHierarchy_HasLink_VisitedNode(t *testing.T) {
	rh := newTestHierarchy()
	// 构建继承链: a -> b -> c
	_ = rh.AddLink("a", "b")
	_ = rh.AddLink("b", "c")

	// 搜索不存在的目标会遍历所有节点
	assert.False(t, rh.HasLink("a", "nonexistent"))
	assert.False(t, rh.HasLink("b", "nonexistent"))
}

func TestRoleHierarchy_HasLink_DanglingLink(t *testing.T) {
	rh := newTestHierarchy()
	// 手动创建一个有悬空链接的角色
	role := rh.getOrCreateRole("alice")
	role.AddLink("nonexistent_role")

	// 直接链接仍匹配
	assert.True(t, rh.HasLink("alice", "nonexistent_role"))
	// 但通过悬空链接的间接搜索不会 panic
	assert.False(t, rh.HasLink("alice", "some_other_target"))
}

func TestRoleHierarchy_HasLink_NonExistentRole(t *testing.T) {
	rh := newTestHierarchy()
	assert.False(t, rh.HasLink("nonexistent", "admin"))
}

func TestRoleHierarchy_HasLink_VisitedNodeRevisit(t *testing.T) {
	rh := newTestHierarchy()
	// 构建菱形继承：a → b → d，a → c → d
	// 搜索不存在的目标时，DFS 会两次到达 d，第二次触发 visited 检查
	_ = rh.AddLink("a", "b")
	_ = rh.AddLink("a", "c")
	_ = rh.AddLink("b", "d")
	_ = rh.AddLink("c", "d")

	assert.False(t, rh.HasLink("a", "nonexistent"))
}

func TestRoleHierarchy_GetDomains_NoDomains(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")
	domains := rh.GetDomains("alice")
	assert.Empty(t, domains)
}

func TestRoleHierarchy_GetAllDomains_NoDomains(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")
	domains := rh.GetAllDomains()
	assert.Empty(t, domains)
}

func TestRoleHierarchy_Clear(t *testing.T) {
	rh := newTestHierarchy()
	_ = rh.AddLink("alice", "admin")

	rh.Clear()
	assert.False(t, rh.HasLink("alice", "admin"))
}
