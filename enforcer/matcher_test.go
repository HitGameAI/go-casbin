/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\matcher_test.go
 * @Description: 测试匹配引擎核心逻辑
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"testing"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
)

func newTestMatcherEngine() *MatcherEngine {
	return NewMatcherEngine(logger.NewLogger())
}

// ==================== 基本匹配测试 ====================

func TestMatcherEngine_Match_NoPolicies(t *testing.T) {
	me := newTestMatcherEngine()

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies:    [][]string{},
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// 无策略时，纯 ABAC 表达式匹配
	ok, effects, err := me.Match(mc, `r.sub == "alice"`)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{"allow"}, effects)

	// 不匹配的表达式
	ok, effects, err = me.Match(mc, `r.sub == "bob"`)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, effects)
}

func TestMatcherEngine_Match_BasicACL(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

func TestMatcherEngine_Match_NoMatch(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data2", "r.act": "write",
		},
		Policies: [][]string{
			{"bob", "data2", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, effects)
}

// ==================== 角色继承测试 ====================

func TestMatcherEngine_Match_RoleInheritance(t *testing.T) {
	me := newTestMatcherEngine()

	rm := role.NewRoleManager(logger.NewLogger())
	rm.AddLink("alice", "admin")

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

func TestMatcherEngine_Match_RoleInheritanceWithDomain(t *testing.T) {
	me := newTestMatcherEngine()

	rm := role.NewRoleManager(logger.NewLogger())
	rm.AddLink("alice", "admin", "tenant1")

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read", "r.dom": "tenant1",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")

	// 不同域不应该匹配
	mc2 := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read", "r.dom": "tenant2",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, _, err = me.Match(mc2, "g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== 短路优化测试 ====================

func TestMatcherEngine_Match_ShortCircuit(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read", "allow"},
			{"alice", "data1", "read", "deny"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	ok, effects, err := me.Match(mc, "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	// 短路优化：匹配到第一条 allow 后立即返回，不应包含 deny
	assert.Equal(t, 1, len(effects))
	assert.Equal(t, "allow", effects[0])
}

func TestMatcherEngine_Match_NoShortCircuit(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read", "allow"},
			{"alice", "data1", "read", "deny"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: false,
	}

	ok, effects, err := me.Match(mc, "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	// 无短路：应匹配所有策略
	assert.Equal(t, 2, len(effects))
}

// ==================== eval 表达式测试 ====================

func TestMatcherEngine_Match_EvalExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub_rule", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{`r.sub == "alice"`, "data1", "read"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

// ==================== 逻辑运算测试 ====================

func TestMatcherEngine_Match_OrExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// r.sub == p.sub 为 false，但 r.act == p.act 为 true，|| 应该匹配
	ok, _, err := me.Match(mc, "r.sub == p.sub || r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestMatcherEngine_Match_AndExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// r.sub == p.sub 为 true，但 r.act == p.act 为 false，&& 不应该匹配
	ok, _, err := me.Match(mc, "r.sub == p.sub && r.act == p.act")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== in 运算符测试 ====================

func TestMatcherEngine_Match_InExpression(t *testing.T) {
	me := newTestMatcherEngine()

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice",
		},
		Policies:    [][]string{},
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, _, err := me.Match(mc, `r.sub in ("alice","bob")`)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, _, err = me.Match(mc, `r.sub in ("charlie","bob")`)
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== 自定义函数测试 ====================

func TestMatcherEngine_Match_CustomFunction(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "/v1/users/123", "r.act": "GET",
		},
		Policies: [][]string{
			{"alice", "/v1/users/*", "GET"},
		},
		Assertion: assertion,
		CustomFuncs: map[string]BuiltinFunc{
			"keyMatch3": func(args ...interface{}) (interface{}, error) {
				return true, nil // 简化测试
			},
		},
	}

	ok, _, err := me.Match(mc, "r.sub == p.sub && keyMatch3(r.obj, p.obj) && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// ==================== extractEffect 测试 ====================

func TestMatcherEngine_ExtractEffect(t *testing.T) {
	me := newTestMatcherEngine()

	// 有 eft 字段
	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read", "allow"}, assertion))
	assert.Equal(t, "deny", me.extractEffect([]string{"alice", "data1", "read", "deny"}, assertion))

	// 无 eft 字段，默认 allow
	assertionNoEft := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read"}, assertionNoEft))

	// assertion 为 nil
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read"}, nil))
}

// ==================== buildVariableMap 测试 ====================

func TestMatcherEngine_BuildVariableMap(t *testing.T) {
	me := newTestMatcherEngine()

	request := map[string]interface{}{
		"r.sub": "alice", "r.obj": "data1", "r.act": "read",
	}

	// 无策略行
	vars := me.buildVariableMap(request, nil, nil)
	assert.Equal(t, "alice", vars["r.sub"])
	assert.Equal(t, "data1", vars["r.obj"])

	// 有策略行
	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}
	vars = me.buildVariableMap(request, []string{"admin", "data1", "read"}, assertion)
	assert.Equal(t, "alice", vars["r.sub"])
	assert.Equal(t, "admin", vars["p.sub"])
	assert.Equal(t, "data1", vars["p.obj"])
}

// ==================== resolveValue 测试 ====================

func TestMatcherEngine_ResolveValue(t *testing.T) {
	me := newTestMatcherEngine()

	vars := map[string]interface{}{
		"r.sub": "alice",
	}

	// 直接查找
	assert.Equal(t, "alice", me.resolveValue("r.sub", vars))

	// 字面量（双引号）
	assert.Equal(t, "hello", me.resolveValue(`"hello"`, vars))

	// 字面量（单引号）
	assert.Equal(t, "world", me.resolveValue(`'world'`, vars))

	// 不存在的变量返回原始 token
	assert.Equal(t, "unknown", me.resolveValue("unknown", vars))
}

// ==================== findTopLevelOp 测试 ====================

func TestMatcherEngine_FindTopLevelOp(t *testing.T) {
	me := newTestMatcherEngine()

	// 顶层 ||
	idx := me.findTopLevelOp("a || b", "||")
	assert.Equal(t, 2, idx)

	// 括号内的 || 不应被找到
	idx = me.findTopLevelOp("(a || b) && c", "||")
	assert.Equal(t, -1, idx)

	// 顶层 &&
	idx = me.findTopLevelOp("a && b", "&&")
	assert.Equal(t, 2, idx)

	// 不存在
	idx = me.findTopLevelOp("a == b", "||")
	assert.Equal(t, -1, idx)
}

// ==================== parseFunctionCall 测试 ====================

func TestMatcherEngine_ParseFunctionCall(t *testing.T) {
	me := newTestMatcherEngine()

	// 正常函数调用
	name, args, ok := me.parseFunctionCall("keyMatch3(r.obj, p.obj)")
	assert.True(t, ok)
	assert.Equal(t, "keyMatch3", name)
	assert.Equal(t, []string{"r.obj", "p.obj"}, args)

	// g 函数不应被解析
	_, _, ok = me.parseFunctionCall("g(r.sub, p.sub)")
	assert.False(t, ok)

	// eval 函数不应被解析
	_, _, ok = me.parseFunctionCall("eval(p.sub_rule)")
	assert.False(t, ok)

	// 非函数表达式
	_, _, ok = me.parseFunctionCall("r.sub == p.sub")
	assert.False(t, ok)
}

// ==================== expandEval 测试 ====================

func TestMatcherEngine_ExpandEval(t *testing.T) {
	me := newTestMatcherEngine()

	vars := map[string]interface{}{
		"p.sub_rule": `r.sub == "alice"`,
	}

	result := me.expandEval("eval(p.sub_rule) && r.obj == p.obj", vars)
	assert.Contains(t, result, `r.sub == "alice"`)
	assert.Contains(t, result, "r.obj == p.obj")

	// 不存在的变量保持原样
	result = me.expandEval("eval(p.unknown)", vars)
	assert.Contains(t, result, "eval(p.unknown)")
}
