package enforcer

import (
	"testing"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== 自定义函数（keyMatch3 等）测试 ====================

func TestKeyMatch3BasicEnforce(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = keyMatch3(r.obj, p.obj)
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, user001, ops, /api/users, GET",
		"p, user001, ops, /api/users/{id}, GET",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	ok, err := e.Enforce("user001", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "keyMatch3 should match exact path")

	ok, err = e.Enforce("user001", "ops", "/api/users/123", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "keyMatch3 should match {id} pattern")

	ok, err = e.Enforce("user001", "ops", "/api/orders", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "keyMatch3 should not match unrelated path")
}

func TestKeyMatch3WithRoleInheritance(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, role:admin, ops, /api/users, GET",
		"p, role:admin, ops, /api/users/{id}, *",
		"g, user001, role:admin, ops",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	ok, err := e.Enforce("user001", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "admin should access /api/users via keyMatch3")

	ok, err = e.Enforce("user001", "ops", "/api/users/123", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "admin should access /api/users/{id} via keyMatch3 with wildcard action")

	ok, err = e.Enforce("user001", "ops", "/api/users/456", "DELETE")
	assert.NoError(t, err)
	assert.True(t, ok, "admin should access /api/users/{id} with DELETE via wildcard action")
}

// ==================== 通配符操作（p.act == "*"）测试 ====================

func TestWildcardActionWithRoleInheritance(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && (r.act == p.act || p.act == "*")
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, role:admin, ops, /api/users, *",
		"p, role:viewer, ops, /api/users, GET",
		"g, user001, role:admin, ops",
		"g, user002, role:viewer, ops",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	// admin with * action
	ok, err := e.Enforce("user001", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "admin with * should match GET")

	ok, err = e.Enforce("user001", "ops", "/api/users", "POST")
	assert.NoError(t, err)
	assert.True(t, ok, "admin with * should match POST")

	ok, err = e.Enforce("user001", "ops", "/api/users", "DELETE")
	assert.NoError(t, err)
	assert.True(t, ok, "admin with * should match DELETE")

	// viewer with specific action
	ok, err = e.Enforce("user002", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "viewer should match GET")

	ok, err = e.Enforce("user002", "ops", "/api/users", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "viewer should not match POST")
}

// ==================== keyMatch3 + 通配符操作 组合测试 ====================

func TestKeyMatch3WithWildcardAction(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, role:admin, ops, /api/users/{id}, *",
		"p, role:viewer, ops, /api/users, GET",
		"g, user001, role:admin, ops",
		"g, user002, role:viewer, ops",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	// admin: keyMatch3 + wildcard
	ok, err := e.Enforce("user001", "ops", "/api/users/123", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "admin should access /api/users/123 with any action")

	ok, err = e.Enforce("user001", "ops", "/api/users/456", "DELETE")
	assert.NoError(t, err)
	assert.True(t, ok, "admin should access /api/users/456 with DELETE")

	// viewer: keyMatch3 + specific action
	ok, err = e.Enforce("user002", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "viewer should GET /api/users")

	ok, err = e.Enforce("user002", "ops", "/api/users", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "viewer should not POST /api/users")
}

// ==================== p2 策略段（ABAC 规则）测试 ====================

func TestExtraPolicySegment(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[policy_definition]
p2 = sub_rule, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act || eval(p2.sub_rule) && r.dom == p2.dom && r.obj == p2.obj && r.act == p2.act
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, role:admin, ops, /api/users, GET",
		"g, user001, role:admin, ops",
		"p2, r.sub == \"superuser\", ops, /api/config, GET",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	// RBAC p 段匹配
	ok, err := e.Enforce("user001", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "RBAC policy should match")

	// ABAC p2 段匹配
	ok, err = e.Enforce("superuser", "ops", "/api/config", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "ABAC p2 policy should match superuser")

	// 不匹配 p2 规则
	ok, err = e.Enforce("normaluser", "ops", "/api/config", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "ABAC p2 should not match normal user")
}

// ==================== 完整业务模型测试（keyMatch3 + 通配符 + p2） ====================

func TestFullBusinessModel(t *testing.T) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[policy_definition]
p2 = sub_rule, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*") || eval(p2.sub_rule) && r.dom == p2.dom && keyMatch3(r.obj, p2.obj) && (r.act == p2.act || p2.act == "*")
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		// RBAC 策略
		"p, role:super_admin, ops, /api/*, *",
		"p, role:tenant_admin, ops_t001, /api/tenants/t001, *",
		"p, role:viewer, tenant_t001, /api/data, GET",
		// ABAC 规则
		"p2, r.sub == \"system\", ops, /api/health, GET",
		// 角色继承
		"g, ops001, role:super_admin, ops",
		"g, ops002, role:tenant_admin, ops_t001",
		"g, tenant001, role:viewer, tenant_t001",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	defer e.Close()

	// super_admin: keyMatch3 + wildcard
	ok, err := e.Enforce("ops001", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "super_admin should access /api/users")

	ok, err = e.Enforce("ops001", "ops", "/api/tenants/t001", "DELETE")
	assert.NoError(t, err)
	assert.True(t, ok, "super_admin should access /api/tenants/t001 with any action")

	// tenant_admin: 特定域
	ok, err = e.Enforce("ops002", "ops_t001", "/api/tenants/t001", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "tenant_admin should access t001 in ops_t001 domain")

	ok, err = e.Enforce("ops002", "ops", "/api/users", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "tenant_admin should not access ops domain (wrong domain)")

	// viewer: 只读
	ok, err = e.Enforce("tenant001", "tenant_t001", "/api/data", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "viewer should GET data")

	ok, err = e.Enforce("tenant001", "tenant_t001", "/api/data", "POST")
	assert.NoError(t, err)
	assert.False(t, ok, "viewer should not POST data")

	// ABAC p2 规则
	ok, err = e.Enforce("system", "ops", "/api/health", "GET")
	assert.NoError(t, err)
	assert.True(t, ok, "ABAC p2 should match system user")

	ok, err = e.Enforce("other", "ops", "/api/health", "GET")
	assert.NoError(t, err)
	assert.False(t, ok, "ABAC p2 should not match other user")
}

// ==================== 内置函数直接测试 ====================

func TestBuiltinKeyMatch3Func(t *testing.T) {
	assert.True(t, KeyMatch3("/api/users", "/api/users"), "exact match")
	assert.True(t, KeyMatch3("/api/users/123", "/api/users/{id}"), "path param match")
	assert.True(t, KeyMatch3("/api/users/123/posts", "/api/users/{id}/posts"), "nested path param")
	assert.False(t, KeyMatch3("/api/orders", "/api/users"), "no match")
	assert.True(t, KeyMatch3("/api/users", "/api/*"), "wildcard match")
}

func TestBuiltinKeyMatchFunc(t *testing.T) {
	assert.True(t, KeyMatch("/api/users", "/api/*"), "wildcard match")
	assert.False(t, KeyMatch("/api/users", "/api/orders"), "no match")
}

func TestBuiltinKeyMatch2Func(t *testing.T) {
	assert.True(t, KeyMatch2("/api/users", "/api/:resource"), "colon pattern match")
	assert.True(t, KeyMatch2("/api/users/123", "/api/:resource/:id"), "nested colon pattern")
	assert.False(t, KeyMatch2("/api/users", "/api/orders"), "no match")
}

func TestBuiltinRegexMatchFunc(t *testing.T) {
	assert.True(t, RegexMatch("alice", "^a.*e$"), "regex match")
	assert.False(t, RegexMatch("bob", "^a.*e$"), "regex no match")
}

func TestBuiltinIPMatchFunc(t *testing.T) {
	assert.True(t, IPMatch("192.168.1.1", "192.168.1.0/24"), "IP in subnet")
	assert.False(t, IPMatch("10.0.0.1", "192.168.1.0/24"), "IP not in subnet")
}

func TestBuiltinGlobMatchFunc(t *testing.T) {
	assert.True(t, GlobMatch("/api/users", "/api/*"), "glob match")
	assert.False(t, GlobMatch("/api/users", "/api/orders"), "glob no match")
}
