/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-25 10:36:34
 * @FilePath: \go-casbin\model\model_test.go
 * @Description: 模型核心测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestModel_LoadFromPath_NotFound(t *testing.T) {
	m := NewModel(newTestLogger())
	err := m.LoadFromPath("nonexistent_model.conf")
	assert.Error(t, err)
}

func TestModel_Copy_DeepCopySuccess(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	m.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})

	cp := m.Copy()
	require.NotNil(t, cp)

	// 修改副本不应影响原模型
	cp.GetAssertion("p").AddPolicy([]string{"bob", "data2", "write"})
	assert.Len(t, m.GetAssertion("p").Policies, 1)
	assert.Len(t, cp.GetAssertion("p").Policies, 2)
}

func TestValidatePolicyDefinition_NoTokens(t *testing.T) {
	m := NewModel(newTestLogger())
	// 添加没有 token 的策略定义
	err := m.AddDef("p", "")
	assert.NoError(t, err)

	// 验证应失败
	err = validatePolicyDefinition(m.GetAssertions())
	assert.Error(t, err)
}

func TestValidatePolicyEffect_Empty(t *testing.T) {
	m := NewModel(newTestLogger())
	// 添加空的 effect 定义
	err := m.AddDef("e", "")
	assert.NoError(t, err)

	err = validatePolicyEffect(m.GetAssertions())
	assert.Error(t, err)
}

func TestModel_LoadFromText_ParseError(t *testing.T) {
	m := NewModel(newTestLogger())
	// 超过 bufio.MaxScanTokenSize (64KB) 的行触发 scanner.Err()，使 LoadModelFromText 返回错误
	longLine := strings.Repeat("a", 70000)
	err := m.LoadFromText(longLine)
	assert.Error(t, err)
}

func TestModel_LoadFromPath_ValidationError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "model.conf")
	// 内容可解析但缺少必需段（p/e/m），触发 LoadFromPath 中的 ValidateModel 错误分支
	err := os.WriteFile(path, []byte("r = sub, obj, act"), 0644)
	require.NoError(t, err)

	m := NewModel(newTestLogger())
	err = m.LoadFromPath(path)
	assert.Error(t, err)
}

func TestModel_Copy_DeepCopyError(t *testing.T) {
	m, err := NewModelFromText(testModelText, newTestLogger())
	require.NoError(t, err)

	// 替换 deepCopyFunc 模拟失败，触发 Copy 的回退分支
	orig := deepCopyFunc
	deepCopyFunc = func(dst, src interface{}) error {
		return fmt.Errorf("deep copy failed")
	}
	defer func() { deepCopyFunc = orig }()

	cp := m.Copy()
	require.NotNil(t, cp)
	// 回退分支应通过引用复制 assertions
	assert.NotNil(t, cp.GetAssertion("r"))
}
