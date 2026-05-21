/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\model_test.go
 * @Description: 模型核心测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"testing"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() logger.ILogger {
	return logger.NewLogger()
}

const testModelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

func TestNewModel(t *testing.T) {
	m := NewModel(newTestLogger())
	assert.NotNil(t, m)
	assert.Empty(t, m.GetAssertions())
}

func TestNewModelFromText(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.NotNil(t, m.GetAssertion("r"))
	assert.NotNil(t, m.GetAssertion("p"))
	assert.NotNil(t, m.GetAssertion("g"))
	assert.NotNil(t, m.GetAssertion("e"))
	assert.NotNil(t, m.GetAssertion("m"))
}

func TestNewModelFromText_Invalid(t *testing.T) {
	_, err := NewModelFromText("", newTestLogger())
	assert.Error(t, err)
}

func TestModel_AddDef(t *testing.T) {
	m := NewModel(newTestLogger())
	err := m.AddDef("r", "sub, obj, act")
	assert.NoError(t, err)
	assertion := m.GetAssertion("r")
	assert.NotNil(t, assertion)
	assert.Equal(t, []string{"r.sub", "r.obj", "r.act"}, assertion.Tokens)
}

func TestModel_HasSection(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	assert.True(t, m.HasSection(SectionRequestDefinition))
	assert.True(t, m.HasSection(SectionPolicyDefinition))
	assert.True(t, m.HasSection(SectionRoleDefinition))
	assert.True(t, m.HasSection(SectionPolicyEffect))
	assert.True(t, m.HasSection(SectionMatchers))
	assert.False(t, m.HasSection("x"))
}

func TestModel_ClearPolicies(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	m.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})
	assert.Len(t, m.GetAssertion("p").Policies, 1)

	m.ClearPolicies()
	assert.Empty(t, m.GetAssertion("p").Policies)
}

func TestModel_ToText(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	text := m.ToText()
	assert.Contains(t, text, "[r]")
	assert.Contains(t, text, "[p]")
	assert.Contains(t, text, "[g]")
	assert.Contains(t, text, "[e]")
	assert.Contains(t, text, "[m]")
}

func TestModel_Copy(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	m.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})

	cp := m.Copy()
	assert.NotNil(t, cp)
	assert.Equal(t, m.GetAssertion("p").Policies, cp.GetAssertion("p").Policies)
}

func TestModel_GetValuesForFieldInPolicyAllTypes(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	m.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})
	m.GetAssertion("p").AddPolicy([]string{"bob", "data2", "write"})

	values := m.GetValuesForFieldInPolicyAllTypes(SectionPolicyDefinition, "p.sub")
	assert.Len(t, values, 2)
}

func TestModel_LoadFromText_InvalidModel(t *testing.T) {
	m := NewModel(newTestLogger())
	err := m.LoadFromText("invalid content")
	assert.Error(t, err)
}
