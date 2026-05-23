/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-22 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-22 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_public_policy_test.go
 * @Description: 测试公开接口策略功能
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== RBAC 公开策略测试 ====================

func TestPublicPolicy_RBACBasic(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
			{"/v1/refresh-token", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// anonymous 可以访问公开接口
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /v1/login POST")

	ok, err = e.IsPublicPolicy("/v1/refresh-token", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /v1/refresh-token POST")

	// anonymous 不能访问非公开接口
	ok, err = e.IsPublicPolicy("/v1/users", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "anonymous should not access /v1/users GET")

	ok, err = e.IsPublicPolicy("/v1/login", "DELETE")
	assert.NoError(t, err)
	assert.False(t, ok, "anonymous should not access /v1/login DELETE")
}

func TestPublicPolicy_EmptyPolicies(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 没有配置公开策略时，所有路径都不是公开的
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "no public policy configured, should deny all")

	// GetPublicPolicies 应返回空列表
	policies := e.GetPublicPolicies()
	assert.Empty(t, policies)
}

func TestPublicPolicy_GetPublicPolicies(t *testing.T) {
	expected := [][]string{
		{SubjectAnonymous, "/v1/login", "POST"},
		{SubjectAnonymous, "/v1/refresh-token", "POST"},
	}

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
			{"/v1/refresh-token", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	policies := e.GetPublicPolicies()
	assert.Len(t, policies, 2)
	assert.Equal(t, expected, policies)
}

func TestPublicPolicy_NotPersistedToAdapter(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 公开策略在内存中生效
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 适配器中不应包含 anonymous 的策略（公开策略不应持久化）
	savedPolicies, err := memAdapter.LoadPolicy()
	require.NoError(t, err)
	for _, p := range savedPolicies {
		if strings.HasPrefix(p, "p, anonymous,") {
			t.Fatalf("public policy should not be persisted to adapter, got: %s", p)
		}
	}
}

func TestPublicPolicy_ReloadPolicy(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	// 先保存一些普通策略
	err := memAdapter.SavePolicy([]string{
		"p, alice, data1, read",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 验证公开策略生效
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 验证普通策略也生效
	ok, err = e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)

	// ReloadPolicy 后公开策略应该仍然生效
	err = e.ReloadPolicy()
	require.NoError(t, err)

	ok, err = e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "public policy should still work after ReloadPolicy")

	ok, err = e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "normal policy should still work after ReloadPolicy")
}

func TestPublicPolicy_LoadPolicy(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	err := memAdapter.SavePolicy([]string{
		"p, bob, data2, read",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// LoadPolicy 后公开策略应该仍然生效
	err = e.LoadPolicy()
	require.NoError(t, err)

	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "public policy should still work after LoadPolicy")

	ok, err = e.Enforce("bob", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "normal policy should still work after LoadPolicy")
}

func TestPublicPolicy_WithFileAdapter(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPolicyPath(filepath.Join("..", "resources", "rbac_policy.csv")),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
			{"/v1/register", "POST"},
		}),
		WithAutoSave(false),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 公开策略生效
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = e.IsPublicPolicy("/v1/register", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 文件中的普通策略也生效
	ok, err = e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)

	// anonymous 不能访问非公开资源
	ok, err = e.Enforce("anonymous", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestPublicPolicy_WildcardAction(t *testing.T) {
	e, err := NewEnforcer(
		WithModelText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && (r.act == p.act || p.act == "*")
`),
		WithPublicPolicies([][]string{
			{"/healthz", "*"},
		}),
		WithAutoSave(false),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 通配符 * 应匹配所有动作
	ok, err := e.IsPublicPolicy("/healthz", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /healthz with any method")

	ok, err = e.IsPublicPolicy("/healthz", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /healthz with any method")

	ok, err = e.IsPublicPolicy("/healthz", "DELETE")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /healthz with any method")
}

// ==================== RBAC Domain 公开策略测试 ====================

func TestPublicPolicy_RBACDomain(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacDomainModelPath),
		WithPublicPolicies([][]string{
			{"public", "/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// anonymous 在 public 域可以访问 /v1/login
	ok, err := e.IsPublicPolicy("public", "/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "anonymous should access /v1/login in public domain")

	// anonymous 在其他域不能访问
	ok, err = e.IsPublicPolicy("tenant1", "/v1/login", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "anonymous should not access /v1/login in tenant1 domain")
}

// ==================== 公开策略与普通策略共存测试 ====================

func TestPublicPolicy_CoexistWithNormalPolicy(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	err := memAdapter.SavePolicy([]string{
		"p, admin, /v1/users, GET",
		"g, alice, admin",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 公开策略：anonymous 可访问
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 普通策略：admin 可访问
	ok, err = e.Enforce("admin", "/v1/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 角色继承：alice 属于 admin，可访问
	ok, err = e.Enforce("alice", "/v1/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok)

	// anonymous 不能访问普通策略保护的资源
	ok, err = e.Enforce("anonymous", "/v1/users", "GET")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestPublicPolicy_AddNormalPolicyAfterInit(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 添加普通策略
	err = e.AddPolicy("alice", "/v1/users", "GET")
	assert.NoError(t, err)

	// 公开策略仍然生效
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 新添加的普通策略也生效
	ok, err = e.Enforce("alice", "/v1/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// ==================== 认证免鉴权策略测试 ====================

func TestAuthSkipPolicy_RBACBasic(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
			{"/v1/auth/refresh", "POST"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// authenticated 可以访问认证免鉴权接口
	ok, err := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "authenticated should access /v1/auth/user-info GET")

	ok, err = e.IsAuthSkipPolicy("/v1/auth/refresh", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "authenticated should access /v1/auth/refresh POST")

	// authenticated 不能访问非免鉴权接口
	ok, err = e.IsAuthSkipPolicy("/v1/users", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "authenticated should not access /v1/users via auth-skip")

	ok, err = e.IsAuthSkipPolicy("/v1/auth/user-info", "DELETE")
	assert.NoError(t, err)
	assert.False(t, ok, "authenticated should not access /v1/auth/user-info DELETE")
}

func TestAuthSkipPolicy_EmptyPolicies(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 没有配置认证免鉴权策略时，所有路径都不是免鉴权的
	ok, err := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.False(t, ok)

	policies := e.GetAuthSkipPolicies()
	assert.Empty(t, policies)
}

func TestAuthSkipPolicy_GetAuthSkipPolicies(t *testing.T) {
	expected := [][]string{
		{SubjectAuthenticated, "/v1/auth/user-info", "GET"},
	}

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	policies := e.GetAuthSkipPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, expected, policies)
}

func TestAuthSkipPolicy_NotPersistedToAdapter(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 认证免鉴权策略在内存中生效
	ok, err := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 适配器中不应包含 authenticated 的策略
	savedPolicies, err := memAdapter.LoadPolicy()
	require.NoError(t, err)
	for _, p := range savedPolicies {
		if strings.HasPrefix(p, "p, authenticated,") {
			t.Fatalf("auth-skip policy should not be persisted to adapter, got: %s", p)
		}
	}
}

func TestAuthSkipPolicy_ReloadPolicy(t *testing.T) {
	memAdapter := policy.NewMemoryAdapter()

	err := memAdapter.SavePolicy([]string{
		"p, alice, data1, read",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithAdapter(memAdapter),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// ReloadPolicy 后认证免鉴权策略应该仍然生效
	err = e.ReloadPolicy()
	require.NoError(t, err)

	ok, err := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "auth-skip policy should still work after ReloadPolicy")
}

func TestAuthSkipPolicy_CoexistWithPublicPolicy(t *testing.T) {
	e, err := NewEnforcer(
		WithModelPath(rbacModelPath),
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
		}),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })

	// 公开策略生效
	ok, err := e.IsPublicPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 认证免鉴权策略生效
	ok, err = e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.True(t, ok)

	// 互不干扰：公开接口不是免鉴权接口
	ok, err = e.IsAuthSkipPolicy("/v1/login", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "/v1/login is public but not auth-skip")

	// 免鉴权接口不是公开接口
	ok, err = e.IsPublicPolicy("/v1/auth/user-info", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "/v1/auth/user-info is auth-skip but not public")
}
