/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 23:21:23
 * @FilePath: \go-casbin\enforcer\enforcer_security_test.go
 * @Description: 测试执行器安全校验
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
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

// ==================== evaluateEffectFromResults 测试 ====================

func TestEvaluateEffectFromResults(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	// some(where (p.eft == allow)) 模式，有 allow 结果
	result, err := e.evaluateEffectFromResults([]string{"allow"})
	assert.NoError(t, err)
	assert.True(t, bool(result))

	// 无匹配策略
	result, err = e.evaluateEffectFromResults([]string{})
	assert.NoError(t, err)
	assert.False(t, bool(result))

	// deny 效果
	result, err = e.evaluateEffectFromResults([]string{"deny"})
	assert.NoError(t, err)
	assert.False(t, bool(result))
}

func TestEvaluateEffectFromResults_NoEffectSection(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	_ = m.AddDef("p", "sub, obj, act")
	_ = m.AddDef("m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	// 没有 e 段时，默认返回 allow
	result, err := e.evaluateEffectFromResults([]string{"allow"})
	assert.NoError(t, err)
	assert.True(t, bool(result))
}

// ==================== evaluateEffect 测试 ====================

func TestEvaluateEffect(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	result, err := e.evaluateEffect()
	assert.NoError(t, err)
	assert.True(t, bool(result), "should allow when policies exist with allow effect")
}

func TestEvaluateEffect_NoPolicyAssertion(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	_ = m.AddDef("p", "sub, obj, act")
	_ = m.AddDef("e", "some(where (p.eft == allow))")
	_ = m.AddDef("m", "r.sub == p.sub")

	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	result, err := e.evaluateEffect()
	assert.NoError(t, err)
	assert.False(t, bool(result))
}

// ==================== handlePolicyChange 测试 ====================

func TestHandlePolicyChange(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	initialCount := len(e.GetPolicy())

	event := policy.NewChangeEvent(policy.EventTypePolicyAdded, "p", "test-node")
	event.NewPolicy = []string{"bob", "data2", "write"}

	e.handlePolicyChange(event)

	assert.Equal(t, initialCount, len(e.GetPolicy()))
}

// ==================== GetNotifier / SetNotifier 测试 ====================

func TestGetNotifier_Nil(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	assert.Nil(t, e.GetNotifier())
}

func TestSetNotifier(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	notifier := &mockNotifier{}
	err := e.SetNotifier(notifier)
	require.NoError(t, err)
	assert.Equal(t, notifier, e.GetNotifier())
	assert.True(t, notifier.subscribed)

	err = e.SetNotifier(nil)
	require.NoError(t, err)
	assert.Nil(t, e.GetNotifier())
}

func TestSetNotifier_Replace(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	oldNotifier := &mockNotifier{}
	err := e.SetNotifier(oldNotifier)
	require.NoError(t, err)

	newNotifier := &mockNotifier{}
	err = e.SetNotifier(newNotifier)
	require.NoError(t, err)
	assert.True(t, oldNotifier.closed, "old notifier should be closed")
	assert.True(t, newNotifier.subscribed, "new notifier should be subscribed")
}

// mockNotifier 用于测试的模拟通知器
type mockNotifier struct {
	subscribed bool
	closed     bool
	publishErr error
}

func (m *mockNotifier) Publish(_ context.Context, _ *policy.ChangeEvent) error {
	return m.publishErr
}

func (m *mockNotifier) Subscribe(_ context.Context, _ policy.ChangeEventHandler) error {
	m.subscribed = true
	return nil
}

func (m *mockNotifier) Unsubscribe() error {
	return nil
}

func (m *mockNotifier) Close() error {
	m.closed = true
	return nil
}

// ==================== notifyPolicyChange 测试 ====================

func TestNotifyPolicyChange_WithNotifier(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	notifier := &mockNotifier{}
	err := e.SetNotifier(notifier)
	require.NoError(t, err)

	e.EnableAutoNotifyWatcher(true)
	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, []string{"alice", "data1", "read"})
}

func TestNotifyPolicyChange_NoNotifier(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, nil)
}

func TestNotifyPolicyChange_Disabled(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	notifier := &mockNotifier{}
	err := e.SetNotifier(notifier)
	require.NoError(t, err)

	e.EnableAutoNotifyWatcher(false)
	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, nil)
}

// ==================== getRequestTokens 测试 ====================

func TestGetRequestTokens(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	tokens := e.getRequestTokens()
	assert.Equal(t, []string{"r.sub", "r.obj", "r.act"}, tokens)
}

func TestGetRequestTokens_NoRequestSection(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	tokens := e.getRequestTokens()
	assert.Nil(t, tokens)
}

// ==================== getPolicyAssertion 测试 ====================

func TestGetPolicyAssertion(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	assertion := e.getPolicyAssertion()
	require.NotNil(t, assertion)
	assert.Equal(t, []string{"p.sub", "p.obj", "p.act"}, assertion.Tokens)
}

func TestGetPolicyAssertion_NoPolicy(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	assertion := e.getPolicyAssertion()
	assert.Nil(t, assertion)
}

// ==================== getMatcherExpression 测试 ====================

func TestGetMatcherExpression(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	expr := e.getMatcherExpression()
	assert.NotEmpty(t, expr)
}

func TestGetMatcherExpression_NoMatcher(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	expr := e.getMatcherExpression()
	assert.Empty(t, expr)
}

// ==================== computeShortCircuit 测试 ====================

func TestComputeShortCircuit(t *testing.T) {
	tests := []struct {
		name         string
		effectExpr   string
		shortCircuit bool
	}{
		{"some where allow", "some(where (p.eft == allow))", true},
		{"some where deny", "some(where (p.eft == deny))", false},
		{"not some where deny", "!some(where (p.eft == deny))", false},
		{"empty expression", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := model.NewModel(logger.NoLogger)
			_ = m.AddDef("r", "sub, obj, act")
			_ = m.AddDef("p", "sub, obj, act")
			_ = m.AddDef("e", tt.effectExpr)
			_ = m.AddDef("m", "r.sub == p.sub")

			evaluator := policy.NewEffectEvaluator(tt.effectExpr)

			e := &Enforcer{
				model:           m,
				logger:          logger.NoLogger,
				effectEvaluator: evaluator,
			}
			result := e.computeShortCircuit()
			assert.Equal(t, tt.shortCircuit, result)
		})
	}
}

// ==================== validatePolicyRule 测试 ====================

func TestValidatePolicyRule_Coverage(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	tests := []struct {
		name    string
		rule    []string
		wantErr bool
	}{
		{"valid rule", []string{"alice", "data1", "read"}, false},
		{"empty rule", []string{}, true},
		{"nil rule", nil, true},
		{"empty field", []string{"alice", "", "read"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.validatePolicyRule("p", "p", tt.rule)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ==================== SetRoleManager 测试 ====================

func TestSetRoleManager(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	newRM := role.NewRoleManager(logger.NoLogger)
	e.SetRoleManager(newRM)
	assert.Equal(t, newRM, e.GetRoleManager())
}

// ==================== SetAdapter 测试 ====================

func TestSetAdapter(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	// 从文件加载的 enforcer 有内置适配器
	assert.NotNil(t, e.GetAdapter())

	mockAdapter := policy.NewMemoryAdapter()
	e.SetAdapter(mockAdapter)
	assert.Equal(t, mockAdapter, e.GetAdapter())
}

// ==================== GetBreaker 测试 ====================

func TestGetBreaker(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	// 默认无 breaker
	assert.Nil(t, e.GetBreaker())
}

// ==================== GetWatcher 测试 ====================

func TestGetWatcher(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	assert.Nil(t, e.GetWatcher())
}

// ==================== LoadFilteredPolicy 测试 ====================

func TestLoadFilteredPolicy(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	// 从文件加载的 enforcer 有内置适配器，LoadFilteredPolicy 应正常执行
	err := e.LoadFilteredPolicy(nil)
	assert.NoError(t, err)
}

// ==================== SavePolicy 测试 ====================

func TestSavePolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	// 从文件加载的 enforcer 有内置适配器，SavePolicy 应正常执行
	err := e.SavePolicy()
	assert.NoError(t, err)
}

// ==================== SetMonitor 测试 ====================

func TestSetMonitor(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	e.SetMonitor("test-monitor")
	assert.Equal(t, "test-monitor", e.monitor)
}

// ==================== executeWithBreaker 测试 ====================

func TestExecuteWithBreaker(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	// 需要初始化 breaker
	e.breaker = breaker.New("test-breaker", breaker.Config{MaxFailures: 5, ResetTimeout: time.Second})

	// 正常执行
	result, err := e.executeWithBreaker(func() (bool, error) {
		return true, nil
	})
	assert.NoError(t, err)
	assert.True(t, result)

	// 函数返回 false
	result, err = e.executeWithBreaker(func() (bool, error) {
		return false, nil
	})
	assert.NoError(t, err)
	assert.False(t, result)
}

// ==================== evaluateEffectFromResultsCached 测试 ====================

func TestEvaluateEffectFromResultsCached(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	// 有 allow 结果
	result, err := e.evaluateEffectFromResultsCached([]string{"allow"})
	assert.NoError(t, err)
	assert.True(t, bool(result))

	// 无结果
	result, err = e.evaluateEffectFromResultsCached([]string{})
	assert.NoError(t, err)
	assert.False(t, bool(result))

	// deny 结果
	result, err = e.evaluateEffectFromResultsCached([]string{"deny"})
	assert.NoError(t, err)
	assert.False(t, bool(result))
}

// ==================== handlePolicyChange 完整覆盖 ====================

func TestHandlePolicyChange_Removed(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	event := policy.NewChangeEvent(policy.EventTypePolicyRemoved, "p", "test-node")
	event.OldPolicy = []string{"alice", "data1", "read"}

	e.handlePolicyChange(event)
}

func TestHandlePolicyChange_Updated(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	event := policy.NewChangeEvent(policy.EventTypePolicyUpdated, "p", "test-node")
	event.OldPolicy = []string{"alice", "data1", "read"}
	event.NewPolicy = []string{"alice", "data2", "write"}

	e.handlePolicyChange(event)
}

func TestHandlePolicyChange_GroupAdded(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	event := policy.NewChangeEvent(policy.EventTypePolicyAdded, "g", "test-node")
	event.NewPolicy = []string{"alice", "admin"}

	e.handlePolicyChange(event)
}

func TestHandlePolicyChange_GroupRemoved(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	event := policy.NewChangeEvent(policy.EventTypePolicyRemoved, "g", "test-node")
	event.OldPolicy = []string{"alice", "admin"}

	e.handlePolicyChange(event)
}

// ==================== doEnforce 边界测试 ====================

func TestDoEnforce_EmptyMatcher(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	_ = m.AddDef("p", "sub, obj, act")
	// 不添加 m 段

	e := &Enforcer{
		model:       m,
		logger:      logger.NoLogger,
		matcherExpr: "", // 空 matcher
	}
	e.mu = sync.RWMutex{}

	_, err := e.doEnforce(context.Background(), "alice", "data1", "read")
	assert.Error(t, err)
}

func TestDoEnforce_NoPolicyAssertion(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	// 不添加 p 段
	_ = m.AddDef("m", "r.sub == p.sub")

	e := &Enforcer{
		model:       m,
		logger:      logger.NoLogger,
		matcherExpr: "r.sub == p.sub",
	}
	e.mu = sync.RWMutex{}

	_, err := e.doEnforce(context.Background(), "alice", "data1", "read")
	assert.Error(t, err)
}

func TestDoEnforce_NilRequest(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	_ = m.AddDef("p", "sub, obj, act")
	_ = m.AddDef("m", "r.sub == p.sub")

	e := &Enforcer{
		model:         m,
		logger:        logger.NoLogger,
		matcherExpr:   "r.sub == p.sub",
		requestTokens: nil, // 导致 buildRequest 返回 nil
	}
	e.mu = sync.RWMutex{}

	_, err := e.doEnforce(context.Background(), "alice", "data1", "read")
	assert.Error(t, err)
}

// ==================== evaluateEffectFromResultsCached 降级测试 ====================

func TestEvaluateEffectFromResultsCached_NilEvaluator(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	// 强制设置 effectEvaluator 为 nil，测试降级路径
	e.effectEvaluator = nil

	result, err := e.evaluateEffectFromResultsCached([]string{"allow"})
	assert.NoError(t, err)
	assert.True(t, bool(result))
}

// ==================== getRequestTokens 回退测试 ====================

func TestGetRequestTokens_FallbackLookup(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	// 使用非标准 key 添加 r 段
	_ = m.AddDef("r2", "sub, obj, act")

	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	tokens := e.getRequestTokens()
	// 回退查找应该能找到 r2 段
	assert.NotNil(t, tokens)
}

// ==================== getPolicyAssertion 回退测试 ====================

func TestGetPolicyAssertion_FallbackLookup(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	// 使用 SectionPolicyDefinition 作为 key
	_ = m.AddDef("p", "sub, obj, act")

	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	assertion := e.getPolicyAssertion()
	assert.NotNil(t, assertion)
}

// ==================== validatePolicyRule g段测试 ====================

func TestValidatePolicyRule_GroupSegment(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	// g 段不强制校验字段数量
	err := e.validatePolicyRule("g", "g", []string{"alice", "admin", "extra_field"})
	assert.NoError(t, err)
}

func TestValidatePolicyRule_NoAssertion(t *testing.T) {
	m := model.NewModel(logger.NoLogger)
	_ = m.AddDef("r", "sub, obj, act")
	// 不添加 p 段

	e := &Enforcer{
		model:  m,
		logger: logger.NoLogger,
	}

	// 无 p 段断言时，应跳过字段数量校验
	err := e.validatePolicyRule("p", "p", []string{"alice", "data1"})
	assert.NoError(t, err)
}

// ==================== computeShortCircuit nil evaluator 测试 ====================

func TestComputeShortCircuit_NilEvaluator(t *testing.T) {
	e := &Enforcer{
		effectEvaluator: nil,
		logger:          logger.NoLogger,
	}

	result := e.computeShortCircuit()
	assert.False(t, result)
}

// ==================== LoadPolicy 错误路径测试 ====================

func TestLoadPolicy_Error(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	// 设置一个会失败的适配器
	e.SetAdapter(&failingAdapter{})

	err := e.LoadPolicy()
	assert.Error(t, err)
}

// failingAdapter 总是返回错误的适配器
type failingAdapter struct{}

func (f *failingAdapter) LoadPolicy() ([]string, error) {
	return nil, fmt.Errorf("adapter load failed")
}

func (f *failingAdapter) SavePolicy(policies []string) error {
	return fmt.Errorf("adapter save failed")
}

func (f *failingAdapter) AddPolicy(line string) error {
	return fmt.Errorf("not supported")
}

func (f *failingAdapter) RemovePolicy(line string) error {
	return fmt.Errorf("not supported")
}

// ==================== LoadFilteredPolicy 错误路径测试 ====================

func TestLoadFilteredPolicy_Error(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)

	e.SetAdapter(&failingAdapter{})

	err := e.LoadFilteredPolicy(nil)
	assert.Error(t, err)
}
