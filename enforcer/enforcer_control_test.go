/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 23:17:00
 * @FilePath: \go-casbin\enforcer\enforcer_control_test.go
 * @Description: 测试控制模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
