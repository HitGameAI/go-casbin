/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_security_test.go
 * @Description: 测试执行器安全校验
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"testing"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== 请求参数安全校验测试 ====================

func buildSecurityTestEnforcer(t *testing.T) *Enforcer {
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
		"p, role:admin, ops, /api/users, *",
		"g, user001, role:admin, ops",
	})
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(false),
		WithEnabled(true),
	)
	require.NoError(t, err)
	return e
}

func TestValidateRequest_EmptyParams(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 无参数应返回错误
	_, err := e.Enforce()
	assert.Error(t, err, "Enforce with no params should return error")
	assert.Contains(t, err.Error(), "invalid enforce request", "error should mention invalid request")
}

func TestValidateRequest_EmptyString(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 空字符串参数应返回错误
	_, err := e.Enforce("", "ops", "/api/users", "GET")
	assert.Error(t, err, "Enforce with empty sub should return error")
	assert.Contains(t, err.Error(), "empty string", "error should mention empty string")

	_, err = e.Enforce("user001", "", "/api/users", "GET")
	assert.Error(t, err, "Enforce with empty dom should return error")

	_, err = e.Enforce("user001", "ops", "", "GET")
	assert.Error(t, err, "Enforce with empty obj should return error")

	_, err = e.Enforce("user001", "ops", "/api/users", "")
	assert.Error(t, err, "Enforce with empty act should return error")
}

func TestValidateRequest_WrongParamCount(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 参数数量不匹配应返回错误
	_, err := e.Enforce("user001", "ops")
	assert.Error(t, err, "Enforce with wrong param count should return error")
	assert.Contains(t, err.Error(), "expected 4 parameters", "error should mention expected count")

	_, err = e.Enforce("user001", "ops", "/api/users", "GET", "extra")
	assert.Error(t, err, "Enforce with too many params should return error")
}

func TestValidateRequest_ValidParams(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 有效参数应正常执行
	ok, err := e.Enforce("user001", "ops", "/api/users", "GET")
	assert.NoError(t, err, "Valid params should not return error")
	assert.True(t, ok, "user001 should have access")
}

// ==================== 策略规则安全校验测试 ====================

func TestValidatePolicyRule_EmptyRule(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	err := e.AddPolicy()
	assert.Error(t, err, "AddPolicy with empty rule should return error")
	assert.Contains(t, err.Error(), "invalid policy rule", "error should mention invalid rule")
}

func TestValidatePolicyRule_EmptyField(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 空字段应返回错误
	err := e.AddPolicy("role:admin", "ops", "", "GET")
	assert.Error(t, err, "AddPolicy with empty field should return error")
	assert.Contains(t, err.Error(), "empty", "error should mention empty field")
}

func TestValidatePolicyRule_WrongFieldCount(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 字段数量不匹配应返回错误
	err := e.AddPolicy("role:admin", "ops")
	assert.Error(t, err, "AddPolicy with wrong field count should return error")
	assert.Contains(t, err.Error(), "expected 4 fields", "error should mention expected field count")
}

func TestValidatePolicyRule_ValidRule(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 有效规则应正常添加
	err := e.AddPolicy("role:editor", "ops", "/api/posts", "GET")
	assert.NoError(t, err, "Valid policy rule should be added")
}

func TestValidatePolicyRule_BatchEmptyField(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// 批量添加中有一条规则包含空字段应返回错误
	err := e.AddPolicies([][]string{
		{"role:editor", "ops", "/api/posts", "GET"},
		{"role:viewer", "ops", "", "GET"}, // 空字段
	})
	assert.Error(t, err, "AddPolicies with empty field should return error")
}

func TestValidatePolicyRule_UpdateFilteredPolicies(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// UpdateFilteredPolicies 中包含无效规则应返回错误
	err := e.UpdateFilteredPolicies([][]string{
		{"role:admin", "ops", "", "GET"}, // 空字段
	}, 0, "role:admin")
	assert.Error(t, err, "UpdateFilteredPolicies with empty field should return error")
}

func TestValidatePolicyRule_SelfAddPolicy(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// SelfAddPolicy 中包含无效规则应返回错误
	err := e.SelfAddPolicy("p", "p", []string{"role:admin", "ops", "", "GET"})
	assert.Error(t, err, "SelfAddPolicy with empty field should return error")
}

func TestValidatePolicyRule_SelfAddPolicies(t *testing.T) {
	e := buildSecurityTestEnforcer(t)
	defer e.Close()

	// SelfAddPolicies 中包含无效规则应返回错误
	err := e.SelfAddPolicies("p", "p", [][]string{
		{"role:editor", "ops", "/api/posts", "GET"},
		{"role:viewer", "ops", "", "GET"},
	})
	assert.Error(t, err, "SelfAddPolicies with empty field should return error")
}
