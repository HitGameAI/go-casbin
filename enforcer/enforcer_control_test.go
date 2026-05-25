/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-25 10:15:20
 * @FilePath: \go-casbin\enforcer\enforcer_control_test.go
 * @Description: 测试控制模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 测试用 matcher 表达式常量
const (
	controlMatcherACLShort = "r.sub == p.sub && r.obj == p.obj"
)

func TestEnforcerEnable(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	assert.True(t, e.IsEnabled(), "enforcer should be enabled initially")
	assert.Equal(t, StateReady, e.GetState(), "state should be ready initially")

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should read data1 when enabled")

	e.Enable(false)
	assert.False(t, e.IsEnabled(), "enforcer should be disabled after Enable(false)")

	_, err = e.Enforce("alice", "data1", "read")
	assert.Error(t, err, "should error when enforcer is disabled")

	e.Enable(true)
	assert.True(t, e.IsEnabled(), "enforcer should be enabled after Enable(true)")
	assert.Equal(t, StateReady, e.GetState(), "state should be ready after re-enabling")

	ok, err = e.Enforce("alice", "data1", "read")
	assert.NoError(t, err, "enforce should not error after re-enabling")
	assert.True(t, ok, "alice should read data1 after re-enabling")
}

func TestEnforcerAutoSave(t *testing.T) {
	e := newMemoryEnforcer(t, aclModelPath)

	assert.True(t, e.IsAutoSave(), "autoSave should be true by default in memory enforcer")

	e.EnableAutoSave(false)
	assert.False(t, e.IsAutoSave())

	e.EnableAutoSave(true)
	assert.True(t, e.IsAutoSave())
}

func TestEnforcerAutoBuildRoleLinks(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	e.EnableAutoBuildRoleLinks(false)

	err := e.AddGroupingPolicy("newuser", "admin")
	assert.NoError(t, err)

	e.EnableAutoBuildRoleLinks(true)
}

func TestEnforcerGetState(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	state := e.GetState()
	assert.Equal(t, StateReady, state, "new enforcer should be in ready state")
}

func TestEnforcerReloadPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.ReloadPolicy()
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "should still work after reload")
}

func TestEnforcerClearPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	e.ClearPolicy()

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "should deny after clearing policy")
}

func TestEnforcerBuildRoleLinks(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	err := e.BuildRoleLinks()
	assert.NoError(t, err)

	roles := e.GetRolesForUser("alice")
	assert.Contains(t, roles, "admin", "alice should have admin role after building role links")
}

func TestEnforcerGetModel(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	m := e.GetModel()
	assert.NotNil(t, m, "model should not be nil")
}

func TestEnforcerGetRoleManager(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	rm := e.GetRoleManager()
	assert.NotNil(t, rm, "role manager should not be nil")
}

func TestEnforcerGetAdapter(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	adapter := e.GetAdapter()
	assert.NotNil(t, adapter, "adapter should not be nil")
}

func TestEnforcerGetPolicyManager(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	pm := e.GetPolicyManager()
	assert.NotNil(t, pm, "policy manager should not be nil")
}

func TestEnforcerGetAllSubjects(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	subjects := e.GetAllSubjects()
	assert.Contains(t, subjects, "alice")
	assert.Contains(t, subjects, "bob")
}

func TestEnforcerGetAllObjects(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	objects := e.GetAllObjects()
	assert.Contains(t, objects, "data1")
	assert.Contains(t, objects, "data2")
}

func TestEnforcerGetAllActions(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	actions := e.GetAllActions()
	assert.Contains(t, actions, "read")
	assert.Contains(t, actions, "write")
}

func TestEnforcerGetAllUsers(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	users := e.GetAllUsers()
	assert.NotEmpty(t, users)
}

// ==================== Self API 测试 ====================

func TestSelfAddPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	initialCount := len(e.GetPolicy())

	err := e.SelfAddPolicy("p", "p", []string{"eve", "data3", "read"})
	assert.NoError(t, err)
	assert.Equal(t, initialCount+1, len(e.GetPolicy()))
}

func TestSelfAddPolicy_Invalid(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.SelfAddPolicy("p", "p", []string{"", "data3", "read"})
	assert.Error(t, err)
}

func TestSelfAddPolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	initialCount := len(e.GetPolicy())

	err := e.SelfAddPolicies("p", "p", [][]string{
		{"eve", "data3", "read"},
		{"carol", "data4", "write"},
	})
	assert.NoError(t, err)
	assert.Equal(t, initialCount+2, len(e.GetPolicy()))
}

func TestSelfAddPoliciesEx(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 添加已存在的策略应跳过
	err := e.SelfAddPoliciesEx("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"eve", "data3", "read"},
	})
	assert.NoError(t, err)
}

func TestSelfRemovePolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	initialCount := len(e.GetPolicy())

	err := e.SelfRemovePolicy("p", "p", []string{"alice", "data1", "read"})
	assert.NoError(t, err)
	assert.Equal(t, initialCount-1, len(e.GetPolicy()))
}

func TestSelfRemovePolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	initialCount := len(e.GetPolicy())

	err := e.SelfRemovePolicies("p", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
	})
	assert.NoError(t, err)
	assert.Equal(t, initialCount-2, len(e.GetPolicy()))
}

func TestSelfRemoveFilteredPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	initialCount := len(e.GetPolicy())

	err := e.SelfRemoveFilteredPolicy("p", "p", 0, "alice")
	assert.NoError(t, err)
	assert.Less(t, len(e.GetPolicy()), initialCount)
}

func TestSelfUpdatePolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.SelfUpdatePolicy("p", "p",
		[]string{"alice", "data1", "read"},
		[]string{"alice", "data1", "write"})
	assert.NoError(t, err)

	ok, _ := e.Enforce("alice", "data1", "write")
	assert.True(t, ok)
}

func TestSelfUpdatePolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.SelfUpdatePolicies("p", "p",
		[][]string{{"alice", "data1", "read"}, {"alice", "data1", "write"}},
		[][]string{{"alice", "data2", "read"}, {"alice", "data2", "write"}})
	assert.NoError(t, err)
}

func TestHasNamedGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	assert.True(t, e.HasNamedGroupingPolicy("g", "alice", "admin"))
	assert.False(t, e.HasNamedGroupingPolicy("g", "nobody", "admin"))
}

// ==================== EnforceWithMatcher / BatchEnforceWithMatcher 测试 ====================

func TestEnforceWithMatcher(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// 使用自定义 matcher 表达式
	ok, err := e.EnforceWithMatcher(controlMatcherACLShort, "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 不匹配
	ok, err = e.EnforceWithMatcher(controlMatcherACLShort, "bob", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestEnforceWithMatcher_EmptyExpr(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// 空 matcher 表达式应回退到默认
	ok, err := e.EnforceWithMatcher("", "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestBatchEnforceWithMatcher(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"eve", "data3", "read"},
	}

	results, err := e.BatchEnforceWithMatcher(controlMatcherACLShort, requests)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(results))
	assert.True(t, results[0])  // alice 可以读 data1
	assert.True(t, results[1])  // bob 可以写 data2
	assert.False(t, results[2]) // eve 无权限
}

// ==================== EnforceEx / EnforceExWithMatcher 测试 ====================

func TestEnforceEx(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	ok, policy, err := e.EnforceEx("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, policy)
}

func TestEnforceEx_Deny(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	ok, policy, err := e.EnforceEx("eve", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, policy)
}

func TestEnforceExWithMatcher(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	ok, policy, err := e.EnforceExWithMatcher(controlMatcherACLShort, "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, policy)
}

// ==================== BatchEnforce 测试 ====================

func TestBatchEnforce(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"eve", "data3", "read"},
	}

	results, err := e.BatchEnforce(requests)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(results))
	assert.True(t, results[0])
	assert.False(t, results[1]) // bob 没有 data2 write 权限
	assert.False(t, results[2])
}

func TestBatchEnforce_Error(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 参数数量不匹配
	requests := [][]interface{}{
		{"alice"},
	}

	results, err := e.BatchEnforce(requests)
	assert.Error(t, err)
	assert.Nil(t, results)
}

// ==================== doEnforceWithMatcher 内部测试 ====================

func TestDoEnforceWithMatcher_InvalidRequest(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 参数为空
	ok, err := e.EnforceWithMatcher("r.sub == p.sub")
	assert.Error(t, err)
	assert.False(t, ok)
}

// ==================== 0% 覆盖率函数测试 ====================

func TestAddGroupingPoliciesEx(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// AddGroupingPoliciesEx 只添加不冲突的分组策略到 policy，不自动建立角色链接
	err := e.AddGroupingPoliciesEx([][]string{
		{"charlie", "viewer"},
		{"dave", "editor"},
	})
	assert.NoError(t, err)

	// 验证策略已添加到 g 段
	assert.True(t, e.HasGroupingPolicy("charlie", "viewer"))
	assert.True(t, e.HasGroupingPolicy("dave", "editor"))
}

func TestUpdateGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// 先添加一个分组
	err := e.AddGroupingPolicy("charlie", "viewer")
	assert.NoError(t, err)
	assert.True(t, e.HasRoleForUser("charlie", "viewer"))

	// 更新分组
	err = e.UpdateGroupingPolicy([]string{"charlie", "viewer"}, []string{"charlie", "editor"})
	assert.NoError(t, err)
	assert.True(t, e.HasRoleForUser("charlie", "editor"))
}

func TestUpdateGroupingPolicies(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddGroupingPolicy("charlie", "viewer")
	assert.NoError(t, err)
	err = e.AddGroupingPolicy("dave", "editor")
	assert.NoError(t, err)

	err = e.UpdateGroupingPolicies(
		[][]string{{"charlie", "viewer"}, {"dave", "editor"}},
		[][]string{{"charlie", "admin"}, {"dave", "viewer"}},
	)
	assert.NoError(t, err)
	assert.True(t, e.HasRoleForUser("charlie", "admin"))
	assert.True(t, e.HasRoleForUser("dave", "viewer"))
}

func TestGetImplicitUsersForPermission(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	users := e.GetImplicitUsersForPermission("data1", "read")
	assert.NotEmpty(t, users)
	// alice 通过 admin 角色继承
	assert.Contains(t, users, "alice")
}

func TestGetAllUsersByDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	users := e.GetAllUsersByDomain("tenant1")
	// 域可能没有用户，不应 panic
	_ = users
}

func TestGetAllRolesByDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	roles := e.GetAllRolesByDomain("tenant1")
	_ = roles
}

func TestGetAllNamedSubjects(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	subjects := e.GetAllNamedSubjects("p")
	assert.Contains(t, subjects, "alice")
}

func TestGetAllNamedObjects(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	objects := e.GetAllNamedObjects("p")
	assert.Contains(t, objects, "data1")
}

func TestGetAllNamedActions(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	actions := e.GetAllNamedActions("p")
	assert.Contains(t, actions, "read")
}

func TestGetAllNamedRoles(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	roles := e.GetAllNamedRoles("g")
	assert.Contains(t, roles, "admin")
}

func TestGetNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	policies := e.GetNamedPolicy("p")
	assert.NotEmpty(t, policies)
}

func TestGetFilteredNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	policies := e.GetFilteredNamedPolicy("p", 0, "alice")
	assert.NotEmpty(t, policies)
}

func TestGetFilteredGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	policies := e.GetFilteredGroupingPolicy(0, "alice")
	assert.NotEmpty(t, policies)
}

func TestGetNamedGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	policies := e.GetNamedGroupingPolicy("g")
	assert.NotEmpty(t, policies)
}

func TestGetFilteredNamedGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	policies := e.GetFilteredNamedGroupingPolicy("g", 0, "alice")
	assert.NotEmpty(t, policies)
}

func TestHasNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	assert.True(t, e.HasNamedPolicy("p", "alice", "data1", "read"))
	assert.False(t, e.HasNamedPolicy("p", "eve", "data1", "read"))
}

// ==================== 自定义函数和 Named 策略 API 测试 ====================

func TestAddFunction(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	e.AddFunction("custom_func", func(args ...interface{}) (interface{}, error) {
		return true, nil
	})

	fn, ok := e.GetFunction("custom_func")
	assert.True(t, ok)
	assert.NotNil(t, fn)
}

func TestGetFunction_NotFound(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	_, ok := e.GetFunction("nonexistent")
	assert.False(t, ok)
}

func TestAddPoliciesEx(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 添加已存在和不存在的策略，Ex 模式忽略已存在的
	err := e.AddPoliciesEx([][]string{
		{"alice", "data1", "read"}, // 已存在
		{"eve", "data3", "write"},  // 不存在
	})
	assert.NoError(t, err)
	assert.True(t, e.HasNamedPolicy("p", "eve", "data3", "write"))
}

func TestAddNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.AddNamedPolicy("p", "eve", "data3", "write")
	assert.NoError(t, err)
	assert.True(t, e.HasNamedPolicy("p", "eve", "data3", "write"))
}

func TestAddNamedPolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.AddNamedPolicies("p", [][]string{
		{"eve", "data3", "write"},
		{"frank", "data4", "read"},
	})
	assert.NoError(t, err)
}

func TestAddNamedPoliciesEx(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.AddNamedPoliciesEx("p", [][]string{
		{"alice", "data1", "read"}, // 已存在
		{"eve", "data3", "write"},
	})
	assert.NoError(t, err)
}

func TestRemoveNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.RemoveNamedPolicy("p", "alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, e.HasNamedPolicy("p", "alice", "data1", "read"))
}

func TestRemoveNamedPolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.RemoveNamedPolicies("p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})
	assert.NoError(t, err)
}

func TestRemoveFilteredNamedPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.RemoveFilteredNamedPolicy("p", 0, "alice")
	assert.NoError(t, err)
	assert.False(t, e.HasNamedPolicy("p", "alice", "data1", "read"))
}

func TestUpdatePolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	err := e.UpdatePolicies(
		[][]string{{"alice", "data1", "read"}},
		[][]string{{"alice", "data1", "write"}},
	)
	assert.NoError(t, err)
	assert.True(t, e.HasNamedPolicy("p", "alice", "data1", "write"))
}

// ==================== RBAC API 补充测试 ====================

func TestAddRoleForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddRoleForUser("charlie", "viewer")
	assert.NoError(t, err)
	assert.True(t, e.HasRoleForUser("charlie", "viewer"))
}

func TestAddRoleForUser_WithDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddRoleForUser("charlie", "admin", "tenant1")
	assert.NoError(t, err)
}

func TestDeleteRoleForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddRoleForUser("charlie", "viewer")
	assert.NoError(t, err)

	err = e.DeleteRoleForUser("charlie", "viewer")
	assert.NoError(t, err)
	assert.False(t, e.HasRoleForUser("charlie", "viewer"))
}

func TestDeleteRolesForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddRoleForUser("charlie", "viewer")
	assert.NoError(t, err)

	deleted := e.DeleteRolesForUser("charlie")
	assert.NoError(t, deleted)
}

func TestDeleteUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.DeleteUser("alice")
	assert.NoError(t, err)
}

func TestDeleteRole(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.DeleteRole("admin")
	assert.NoError(t, err)
}

func TestGetPermissionsForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	perms := e.GetPermissionsForUser("alice")
	assert.NotEmpty(t, perms)
}

func TestHasPermissionForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	assert.True(t, e.HasPermissionForUser("alice", "data1", "read"))
}

func TestAddPermissionForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddPermissionForUser("eve", "data3", "write")
	assert.NoError(t, err)
	assert.True(t, e.HasPermissionForUser("eve", "data3", "write"))
}

func TestAddPermissionsForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddPermissionsForUser("eve", []string{"data3", "write"}, []string{"data4", "read"})
	assert.NoError(t, err)
}

func TestDeletePermissionForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.DeletePermissionForUser("alice", "data1", "read")
	assert.NoError(t, err)
}

func TestDeletePermissionsForUser(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.DeletePermissionsForUser("alice")
	assert.NoError(t, err)
}

func TestDeletePermission(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.DeletePermission("data1", "read")
	assert.NoError(t, err)
}

func TestGetAllDomains(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	domains := e.GetAllDomains()
	_ = domains
}

func TestRemoveFilteredGroupingPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.RemoveFilteredGroupingPolicy(0, "alice")
	assert.NoError(t, err)
}

func TestEnforceContext(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	ok, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestEnforceContext_Disabled(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	e.Enable(false)
	_, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.Error(t, err)
}

func TestEnforceContext_WithBreaker(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPolicyPath(rbacPolicyPath),
		WithAutoSave(true),
		WithBreaker("test-breaker", breaker.Config{MaxFailures: 5, ResetTimeout: time.Second}),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	ok, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestEnforceContext_WithRetry(t *testing.T) {
	r := retry.NewRetry().SetAttemptCount(3).SetInterval(10 * time.Millisecond)
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPolicyPath(rbacPolicyPath),
		WithAutoSave(true),
		WithRetry(r),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	ok, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// mockUpdatableAdapter 实现 UpdatableAdapter 接口用于测试
type mockUpdatableAdapter struct {
	policy.Adapter
	policies []string
}

func newMockUpdatableAdapter() *mockUpdatableAdapter {
	return &mockUpdatableAdapter{
		Adapter:  policy.NewMemoryAdapter(),
		policies: []string{},
	}
}

func (m *mockUpdatableAdapter) AddPolicy(line string) error {
	m.policies = append(m.policies, line)
	return nil
}

func (m *mockUpdatableAdapter) RemovePolicy(line string) error {
	for i, p := range m.policies {
		if p == line {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			break
		}
	}
	return nil
}

func (m *mockUpdatableAdapter) UpdatePolicy(oldLine, newLine string) error {
	for i, p := range m.policies {
		if p == oldLine {
			m.policies[i] = newLine
			return nil
		}
	}
	return fmt.Errorf("policy not found")
}

func (m *mockUpdatableAdapter) UpdatePolicies(oldLines, newLines []string) error {
	for i, old := range oldLines {
		if i < len(newLines) {
			_ = m.UpdatePolicy(old, newLines[i])
		}
	}
	return nil
}

func (m *mockUpdatableAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	// 简单实现：移除匹配的旧策略，添加新策略
	m.policies = append(m.policies, newLines...)
	return nil
}

func (m *mockUpdatableAdapter) SavePolicy(policies []string) error {
	m.policies = policies
	return nil
}

func (m *mockUpdatableAdapter) LoadPolicy() ([]string, error) {
	return m.policies, nil
}

func TestUpdateFilteredPolicies(t *testing.T) {
	adapter := newMockUpdatableAdapter()
	_ = adapter.SavePolicy([]string{
		"p, alice, data1, read",
		"p, bob, data2, write",
	})

	e, err := NewEnforcer(
		WithModelPath(aclModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	err = e.UpdateFilteredPolicies(
		[][]string{{"alice", "data1", "write"}},
		0, "alice",
	)
	assert.NoError(t, err)
}

func TestUpdateFilteredPolicies_ValidationError(t *testing.T) {
	adapter := newMockUpdatableAdapter()
	_ = adapter.SavePolicy([]string{
		"p, alice, data1, read",
	})

	e, err := NewEnforcer(
		WithModelPath(aclModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	// 空策略规则应触发验证错误
	err = e.UpdateFilteredPolicies(
		[][]string{{}},
		0, "alice",
	)
	assert.Error(t, err)
}

// addFailAdapter AddPolicy 总是失败
type addFailAdapter struct {
	policy.Adapter
}

func newAddFailAdapter() *addFailAdapter {
	return &addFailAdapter{Adapter: policy.NewMemoryAdapter()}
}

func (a *addFailAdapter) AddPolicy(line string) error {
	return fmt.Errorf("adapter add failed")
}

func (a *addFailAdapter) LoadPolicy() ([]string, error) {
	return []string{"p, alice, data1, read"}, nil
}

func (a *addFailAdapter) SavePolicy(policies []string) error {
	return nil
}

func (a *addFailAdapter) RemovePolicy(line string) error {
	return nil
}

func TestAddRoleForUser_AdapterError(t *testing.T) {
	adapter := newAddFailAdapter()
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	// 适配器 AddPolicy 失败时应回滚角色链接
	err = e.AddRoleForUser("charlie", "viewer")
	assert.Error(t, err)
	// 角色链接应被回滚
	assert.False(t, e.HasRoleForUser("charlie", "viewer"))
}

func TestRemoveFilteredGroupingPolicy_NonUpdatableAdapter(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// MemoryAdapter 不实现 UpdatableAdapter，走 RemovePolicy 循环路径
	err := e.RemoveFilteredGroupingPolicy(0, "alice")
	assert.NoError(t, err)
}

func TestRemoveFilteredGroupingPolicy_WithDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddGroupingPolicy("charlie", "viewer", "tenant1")
	assert.NoError(t, err)

	err = e.RemoveFilteredGroupingPolicy(0, "charlie")
	assert.NoError(t, err)
}

func TestEnforceWithMatcher_Disabled(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	e.Enable(false)
	_, err := e.EnforceWithMatcher("r.sub == p.sub", "alice", "data1", "read")
	assert.Error(t, err)
}

func TestEnforceExWithMatcher_Disabled(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	e.Enable(false)
	_, _, err := e.enforceExWithMatcherExpr("r.sub == p.sub", "alice", "data1", "read")
	assert.Error(t, err)
}

func TestBatchEnforceWithMatcher_Disabled(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	e.Enable(false)
	// BatchEnforceWithMatcher 不检查 enabled，直接调用 doEnforceWithMatcher
	// disabled 时策略仍在内存中，enforce 仍会正常执行
	results, err := e.BatchEnforceWithMatcher("r.sub == p.sub && r.obj == p.obj && r.act == p.act", [][]interface{}{{"alice", "data1", "read"}})
	assert.NoError(t, err)
	assert.Equal(t, []bool{true}, results)
}

func TestDeleteDomains_Multiple(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddGroupingPolicy("charlie", "viewer", "tenant1")
	assert.NoError(t, err)
	err = e.AddGroupingPolicy("dave", "editor", "tenant2")
	assert.NoError(t, err)

	err = e.DeleteDomains("tenant1", "tenant2")
	assert.NoError(t, err)
}

func TestDeleteAllUsersByDomain(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	err := e.AddGroupingPolicy("charlie", "viewer", "tenant1")
	assert.NoError(t, err)

	err = e.DeleteAllUsersByDomain("tenant1")
	assert.NoError(t, err)
}

func TestDeleteRolesForUser_NoRoles(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// 用户没有角色时应直接返回 nil
	err := e.DeleteRolesForUser("nonexistent")
	assert.NoError(t, err)
}

func TestGetImplicitUsersForPermission_NoMatch(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// 不存在的权限应返回空
	users := e.GetImplicitUsersForPermission("nonexistent", "noaction")
	assert.Empty(t, users)
}

func TestHasPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	assert.True(t, e.HasPolicy("alice", "data1", "read"))
	assert.False(t, e.HasPolicy("eve", "data3", "write"))
}

func TestNewEnforcer_ModelText(t *testing.T) {
	modelText := `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	e, err := NewEnforcer(WithModelText(modelText))
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()
}

// failUpdateAdapter 的 UpdateFilteredPolicies 总是失败
type failUpdateAdapter struct {
	mockUpdatableAdapter
}

func newFailUpdateAdapter() *failUpdateAdapter {
	return &failUpdateAdapter{mockUpdatableAdapter: *newMockUpdatableAdapter()}
}

func (f *failUpdateAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	return fmt.Errorf("update filtered policies failed")
}

func TestRemoveFilteredGroupingPolicy_WithUpdatableAdapter(t *testing.T) {
	adapter := newMockUpdatableAdapter()
	_ = adapter.SavePolicy([]string{
		"p, alice, data1, read",
		"g, alice, admin",
	})

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	err = e.RemoveFilteredGroupingPolicy(0, "alice")
	assert.NoError(t, err)
}

func TestRemoveFilteredGroupingPolicy_UpdatableAdapterError(t *testing.T) {
	adapter := newFailUpdateAdapter()
	_ = adapter.SavePolicy([]string{
		"p, alice, data1, read",
		"g, alice, admin",
	})

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	err = e.RemoveFilteredGroupingPolicy(0, "alice")
	assert.Error(t, err)
}

func TestAddGroupingPolicy_AdapterError(t *testing.T) {
	adapter := newAddFailAdapter()
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(adapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	defer e.Close()

	err = e.AddGroupingPolicy("charlie", "viewer")
	assert.Error(t, err)
}

func TestEnforceExWithMatcherExpr_EmptyMatcher(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 空 matcher 表达式应使用缓存的 matcherExpr
	ok, policy, err := e.enforceExWithMatcherExpr("", "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotEmpty(t, policy)
}

func TestEnforceExWithMatcherExpr_NoMatch(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	// 不匹配的策略应返回 false
	ok, policy, err := e.enforceExWithMatcherExpr("r.sub == p.sub && r.obj == p.obj && r.act == p.act", "eve", "data3", "write")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, policy)
}

func TestEnforceContext_NotReady(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	defer e.Close()

	e.Enable(false)
	_, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.Error(t, err)
}

func TestValidatePolicyRule_GType(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	defer e.Close()

	// g 段策略不强制校验字段数量
	err := e.validatePolicyRule(model.SectionRoleDefinition, "g", []string{"alice", "admin", "tenant1", "extra"})
	assert.NoError(t, err)
}
