/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer.go
 * @Description: 核心执行器（含熔断、重试、状态机、完整RBAC/Management API）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/idgen"
	"github.com/kamalyes/go-toolbox/pkg/mathx"
	"github.com/kamalyes/go-toolbox/pkg/retry"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// 执行器状态常量
const (
	StateReady    = "ready"    // 就绪状态：正常执行权限校验
	StateDisabled = "disabled" // 禁用状态：所有 Enforce 调用返回错误
	StateError    = "error"    // 错误状态：策略加载失败等异常
)

// Enforcer 核心执行器
// 整合模型、策略、角色、匹配器等模块，提供完整的权限校验能力
// 支持熔断器、重试、状态机、分布式通知等企业级特性
//
// 核心职责：
//   - 权限校验：Enforce/EnforceContext/EnforceEx 等方法
//   - 策略管理：AddPolicy/RemovePolicy/UpdatePolicy 等 CRUD 操作
//   - 角色管理：AddGroupingPolicy/GetRolesForUser 等角色继承操作
//   - 多租户：GetRolesForUserInDomain/GetPermissionsForUserInDomain 等域隔离操作
//   - 生命周期：状态机管理（Ready/Disabled/Error），熔断保护，自动重试
//
// 使用方式：
//
//	e, _ := enforcer.NewEnforcer(
//	    enforcer.WithModelPath("resources/rbac_model.conf"),
//	    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
//	    enforcer.WithLogger(log),
//	)
//	ok, _ := e.Enforce("alice", "data1", "read")
type Enforcer struct {
	mu       sync.RWMutex
	model    *model.Model          // 权限模型（PERM 元模型：r/p/g/e/m 五段）
	policy   *policy.Policy        // 策略管理器（加载/保存/增删改查策略）
	roleMgr  *role.RoleManager     // 角色管理器（RBAC 角色继承链、域支持、缓存）
	matcher  *MatcherEngine        // 匹配器引擎（基于 go-toolbox/matcher，支持 ACL/RBAC/ABAC）
	monitor  interface{}           // 监控接口（预留）
	watcher  *policy.PolicyWatcher // 文件变更监控器（单机模式，检测 CSV 文件变更）
	notifier policy.PolicyNotifier // 分布式策略变更通知器（Pub/Sub，多节点同步）

	stateMachine *syncx.StateMachine[string] // 状态机（管理执行器生命周期：Disabled→Ready→Error）
	breaker      *breaker.Circuit            // 熔断器（保护下游存储，防止级联故障）
	retry        *retry.Retry                // 重试器（指数退避+抖动，自动重试临时性故障）
	idGenerator  idgen.IDGenerator           // ID 生成器（生成 TraceID/SpanID/RequestID 用于追踪）
	logger       logger.ILogger              // 日志记录器（基于 go-logger，支持结构化日志）

	customFuncs map[string]BuiltinFunc // 自定义匹配函数（可在 matcher 表达式中使用）

	autoSave           bool // 是否自动保存策略到适配器（AddPolicy/RemovePolicy 时自动持久化）
	autoBuildRoleLinks bool // 是否自动构建角色继承链（添加 g 策略时自动更新角色关系）
	autoNotifyWatcher  bool // 是否自动通知策略变更（含 Pub/Sub 广播到其他节点）
	enabled            bool // 执行器是否启用（禁用时所有 Enforce 返回 EnforcerDisabledError）
}

// NewEnforcer 创建核心执行器
// 通过 Option 函数模式配置模型路径、策略路径、日志、熔断器、重试器、通知器等
// 创建流程：加载模型 → 初始化角色管理器 → 初始化匹配器 → 加载策略 → 构建角色链 → 启动监控
func NewEnforcer(opts ...Option) (*Enforcer, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	if o.logger == nil {
		o.logger = logger.NewLogger()
	}

	sm := syncx.NewStateMachine[string](StateDisabled)
	sm.AllowTransition(StateDisabled, StateReady)
	sm.AllowTransition(StateReady, StateDisabled)
	sm.AllowTransition(StateReady, StateError)
	sm.AllowTransition(StateError, StateReady)
	sm.AllowTransition(StateError, StateDisabled)

	sm.OnTransition(func(from, to string) {
		o.logger.InfoKV("Enforcer state changed", "from", from, "to", to)
	})

	e := &Enforcer{
		logger:             o.logger,
		autoSave:           o.autoSave,
		autoBuildRoleLinks: true,
		autoNotifyWatcher:  true,
		enabled:            o.enabled,
		breaker:            o.breaker,
		retry:              o.retry,
		stateMachine:       sm,
		idGenerator:        idgen.NewIDGenerator(string(idgen.GeneratorTypeUUID)),
		customFuncs:        make(map[string]BuiltinFunc),
	}

	if o.modelPath != "" {
		m, err := model.NewModelFromPath(o.modelPath, o.logger)
		if err != nil {
			return nil, errors.WrapError("failed to load model", err)
		}
		e.model = m
	} else if o.modelText != "" {
		m, err := model.NewModelFromText(o.modelText, o.logger)
		if err != nil {
			return nil, errors.WrapError("failed to parse model", err)
		}
		e.model = m
	} else {
		return nil, errors.NewModelLoadFailedError("no model source provided")
	}

	e.roleMgr = role.NewRoleManager(o.logger)
	e.matcher = NewMatcherEngine(o.logger)

	var adapter policy.Adapter
	if o.adapter != nil {
		adapter = o.adapter
	} else if o.policyPath != "" {
		adapter = policy.NewFileAdapter(o.policyPath)
	} else {
		adapter = policy.NewMemoryAdapter()
	}

	e.policy = policy.NewPolicy(e.model, adapter, o.logger)

	if err := e.policy.LoadPolicy(); err != nil {
		return nil, errors.WrapError("failed to load policy", err)
	}

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	if o.watcher && o.policyPath != "" {
		e.watcher = policy.NewPolicyWatcher(o.policyPath, o.watchInterval, o.logger)
		e.watcher.AddCallback(func() {
			_ = e.ReloadPolicy()
		})
		_ = e.watcher.Start()
	}

	// 初始化分布式策略变更通知器
	if o.notifier != nil {
		e.notifier = o.notifier
		// 订阅策略变更事件，收到事件后自动重载策略
		if err := e.notifier.Subscribe(context.Background(), e.handlePolicyChange); err != nil {
			o.logger.WarnKV("Failed to subscribe policy notifier", "error", err.Error())
		} else {
			o.logger.InfoKV("Policy notifier subscribed successfully")
		}
	}

	if o.enabled {
		if err := sm.TransitionTo(StateReady); err != nil {
			o.logger.WarnKV("Failed to transition to ready state", "error", err.Error())
		}
	}

	o.logger.InfoKV("Enforcer created successfully",
		"model_sections", len(e.model.GetAssertions()),
		"auto_save", e.autoSave,
		"enabled", e.enabled,
	)

	return e, nil
}

// Close 关闭执行器，释放所有资源
// 停止文件监控器和分布式通知器
func (e *Enforcer) Close() {
	if e.watcher != nil {
		e.watcher.Stop()
	}
	if e.notifier != nil {
		_ = e.notifier.Close()
	}
	e.logger.InfoMsg("Enforcer closed")
}

// ==================== Enforcer API ====================

// Enforce 执行权限校验（不带 context）
// 内部调用 EnforceContext 并传入 context.Background()
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.EnforceContext(context.Background(), rvals...)
}

// EnforceContext 执行权限校验（带 context）
// 核心校验流程：检查状态 → 构建请求 → 匹配策略 → 评估效果
// 支持熔断器保护和重试机制
func (e *Enforcer) EnforceContext(ctx context.Context, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return false, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	if e.stateMachine.CurrentState() != StateReady {
		return false, errors.NewEnforcerNotReadyError(e.stateMachine.CurrentState())
	}

	traceID := e.idGenerator.GenerateTraceID()
	requestID := e.idGenerator.GenerateRequestID()

	enforceFn := func() (bool, error) {
		return e.doEnforce(ctx, rvals...)
	}

	if e.breaker != nil {
		result, err := e.executeWithBreaker(enforceFn)
		if err != nil {
			e.logger.ErrorContextKV(ctx, "Enforce failed with breaker",
				"trace_id", traceID, "request_id", requestID, "error", err.Error())
			return false, err
		}
		return result, nil
	}

	if e.retry != nil {
		var result bool
		var err error
		retryErr := e.retry.Do(func() error {
			result, err = e.doEnforce(ctx, rvals...)
			return err
		})
		if retryErr != nil {
			return false, errors.NewEnforcerRetryExhaustedError(retryErr.Error())
		}
		return result, nil
	}

	result, err := enforceFn()
	if err != nil {
		e.logger.ErrorContextKV(ctx, "Enforce failed",
			"trace_id", traceID, "request_id", requestID, "error", err.Error())
		return false, err
	}

	return result, nil
}

// EnforceWithMatcher 使用自定义匹配表达式执行权限校验
func (e *Enforcer) EnforceWithMatcher(matcherExpr string, rvals ...interface{}) (bool, error) {
	return e.enforceWithMatcherExpr(matcherExpr, rvals...)
}

// EnforceEx 执行权限校验并返回匹配的策略
func (e *Enforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr("", rvals...)
}

// EnforceExWithMatcher 使用自定义匹配表达式执行权限校验并返回匹配的策略
func (e *Enforcer) EnforceExWithMatcher(matcherExpr string, rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr(matcherExpr, rvals...)
}

// BatchEnforce 批量执行权限校验
func (e *Enforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))
	for i, req := range requests {
		result, err := e.Enforce(req...)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// BatchEnforceWithMatcher 使用自定义匹配表达式批量执行权限校验
func (e *Enforcer) BatchEnforceWithMatcher(matcherExpr string, requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))
	for i, req := range requests {
		result, err := e.EnforceWithMatcher(matcherExpr, req...)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

func (e *Enforcer) enforceWithMatcherExpr(matcherExpr string, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return false, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}

	expr := matcherExpr
	if expr == "" {
		expr = e.getMatcherExpression()
	}
	if expr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, errors.NewPolicyNotFoundError("p")
	}

	mc := &MatchContext{
		Request:   request,
		Policies:  policyAssertion.Policies,
		RoleMgr:   e.roleMgr,
		Assertion: policyAssertion,
	}

	matched, matchedEffects, err := e.matcher.Match(mc, expr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffectFromResults(matchedEffects)
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

func (e *Enforcer) enforceExWithMatcherExpr(matcherExpr string, rvals ...interface{}) (bool, []string, error) {
	if !e.enabled {
		return false, nil, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, nil, errors.NewModelInvalidError("invalid request parameters")
	}

	expr := matcherExpr
	if expr == "" {
		expr = e.getMatcherExpression()
	}
	if expr == "" {
		return false, nil, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, nil, errors.NewPolicyNotFoundError("p")
	}

	for i, p := range policyAssertion.Policies {
		vars := e.matcher.buildVariableMap(request, p, policyAssertion)
		exprToEval := expr
		if strings.Contains(exprToEval, "eval(") {
			exprToEval = e.matcher.expandEval(exprToEval, vars)
		}
		if e.matcher.evalExpr(exprToEval, vars, e.roleMgr) {
			return true, p, nil
		}
		_ = i
	}

	return false, nil, nil
}

// ==================== Custom Function ====================

// ==================== 自定义函数 API ====================

// AddFunction 添加自定义匹配函数
// 自定义函数可在 matcher 表达式中使用，扩展匹配能力
// 例如：添加 keyMatch2 函数用于 URL 路径匹配
func (e *Enforcer) AddFunction(name string, fn BuiltinFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customFuncs[name] = fn
	e.logger.InfoKV("Custom function added", "name", name)
}

// GetFunction 获取已注册的自定义匹配函数
func (e *Enforcer) GetFunction(name string) (BuiltinFunc, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	fn, ok := e.customFuncs[name]
	return fn, ok
}

// ==================== 策略管理 API ====================

// AddPolicy 添加一条策略规则
// 同时写入适配器（autoSave）和通知其他节点（autoNotifyWatcher）
func (e *Enforcer) AddPolicy(params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.AddPolicy(model.SectionPolicyDefinition, "p", params); err != nil {
		return err
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "p, " + strings.Join(params, ", ")
		if err := e.policy.GetAdapter().AddPolicy(line); err != nil {
			return errors.WrapError("auto-save policy", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, params)

	return nil
}

// AddPolicies 批量添加策略规则
func (e *Enforcer) AddPolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.AddPolicies(model.SectionPolicyDefinition, "p", rules); err != nil {
		return err
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		if ba, ok := e.policy.GetAdapter().(policy.BatchAdapter); ok {
			var lines []string
			for _, rule := range rules {
				lines = append(lines, "p, "+strings.Join(rule, ", "))
			}
			if err := ba.AddPolicies(lines); err != nil {
				return errors.WrapError("auto-save policies", err)
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, nil)

	return nil
}

// AddPoliciesEx 批量添加策略规则（忽略已存在的规则）
func (e *Enforcer) AddPoliciesEx(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionPolicyDefinition, "p", rules)
}

// AddNamedPolicy 添加指定类型的策略规则
func (e *Enforcer) AddNamedPolicy(ptype string, params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicy(model.SectionPolicyDefinition, ptype, params)
}

// AddNamedPolicies 批量添加指定类型的策略规则
func (e *Enforcer) AddNamedPolicies(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicies(model.SectionPolicyDefinition, ptype, rules)
}

// AddNamedPoliciesEx 批量添加指定类型的策略规则（忽略已存在的规则）
func (e *Enforcer) AddNamedPoliciesEx(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionPolicyDefinition, ptype, rules)
}

// RemovePolicy 删除一条策略规则
func (e *Enforcer) RemovePolicy(params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.RemovePolicy(model.SectionPolicyDefinition, "p", params); err != nil {
		return err
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "p, " + strings.Join(params, ", ")
		if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
			return errors.WrapError("auto-remove policy", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", params, nil)

	return nil
}

// RemovePolicies 批量删除策略规则
func (e *Enforcer) RemovePolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.RemovePolicies(model.SectionPolicyDefinition, "p", rules); err != nil {
		return err
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		if ba, ok := e.policy.GetAdapter().(policy.BatchAdapter); ok {
			var lines []string
			for _, rule := range rules {
				lines = append(lines, "p, "+strings.Join(rule, ", "))
			}
			if err := ba.RemovePolicies(lines); err != nil {
				return errors.WrapError("auto-remove policies", err)
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", nil, nil)

	return nil
}

// RemoveFilteredPolicy 按字段过滤删除策略规则
// fieldIndex: 起始字段索引，fieldValues: 过滤字段值
func (e *Enforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", fieldIndex, fieldValues...)
}

// RemoveNamedPolicy 删除指定类型的策略规则
func (e *Enforcer) RemoveNamedPolicy(ptype string, params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicy(model.SectionPolicyDefinition, ptype, params)
}

// RemoveNamedPolicies 批量删除指定类型的策略规则
func (e *Enforcer) RemoveNamedPolicies(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicies(model.SectionPolicyDefinition, ptype, rules)
}

// RemoveFilteredNamedPolicy 按字段过滤删除指定类型的策略规则
func (e *Enforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, ptype, fieldIndex, fieldValues...)
}

// UpdatePolicy 更新一条策略规则
func (e *Enforcer) UpdatePolicy(oldPolicy, newPolicy []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicy(model.SectionPolicyDefinition, "p", oldPolicy, newPolicy)
}

// UpdatePolicies 批量更新策略规则
func (e *Enforcer) UpdatePolicies(oldPolicies, newPolicies [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicies(model.SectionPolicyDefinition, "p", oldPolicies, newPolicies)
}

// UpdateFilteredPolicies 按过滤条件更新策略规则
func (e *Enforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.policy.GetAdapter() != nil {
		if ua, ok := e.policy.GetAdapter().(policy.UpdatableAdapter); ok {
			var newLines []string
			for _, np := range newPolicies {
				newLines = append(newLines, "p, "+strings.Join(np, ", "))
			}
			return ua.UpdateFilteredPolicies(newLines, fieldIndex, fieldValues...)
		}
	}

	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", fieldIndex, fieldValues...)
}

// ==================== 角色分组策略 API ====================

// AddGroupingPolicy 添加角色分组策略（g 策略）
// 同时更新角色继承链、写入适配器和通知其他节点
func (e *Enforcer) AddGroupingPolicy(params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.AddPolicy(model.SectionRoleDefinition, "g", params); err != nil {
		return err
	}

	if len(params) >= 2 && e.autoBuildRoleLinks {
		if err := e.roleMgr.AddLink(params[0], params[1]); err != nil {
			return err
		}
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "g, " + strings.Join(params, ", ")
		if err := e.policy.GetAdapter().AddPolicy(line); err != nil {
			return errors.WrapError("auto-save grouping policy", err)
		}
	}

	return nil
}

// AddGroupingPolicies 批量添加角色分组策略
func (e *Enforcer) AddGroupingPolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.AddPolicies(model.SectionRoleDefinition, "g", rules); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for _, rule := range rules {
			if len(rule) >= 2 {
				_ = e.roleMgr.AddLink(rule[0], rule[1])
			}
		}
	}

	return nil
}

// AddGroupingPoliciesEx 批量添加角色分组策略（忽略已存在的规则）
func (e *Enforcer) AddGroupingPoliciesEx(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionRoleDefinition, "g", rules)
}

// RemoveGroupingPolicy 删除角色分组策略
// 同时更新角色继承链和从适配器删除
func (e *Enforcer) RemoveGroupingPolicy(params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.RemovePolicy(model.SectionRoleDefinition, "g", params); err != nil {
		return err
	}

	if len(params) >= 2 && e.autoBuildRoleLinks {
		e.roleMgr.DeleteLink(params[0], params[1])
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "g, " + strings.Join(params, ", ")
		if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
			return errors.WrapError("auto-remove grouping policy", err)
		}
	}

	return nil
}

// RemoveGroupingPolicies 批量删除角色分组策略
func (e *Enforcer) RemoveGroupingPolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.RemovePolicies(model.SectionRoleDefinition, "g", rules); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for _, rule := range rules {
			if len(rule) >= 2 {
				e.roleMgr.DeleteLink(rule[0], rule[1])
			}
		}
	}

	return nil
}

// RemoveFilteredGroupingPolicy 按字段过滤删除角色分组策略
func (e *Enforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", fieldIndex, fieldValues...)
}

// UpdateGroupingPolicy 更新角色分组策略
func (e *Enforcer) UpdateGroupingPolicy(oldRule, newRule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.UpdatePolicy(model.SectionRoleDefinition, "g", oldRule, newRule); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		if len(oldRule) >= 2 {
			e.roleMgr.DeleteLink(oldRule[0], oldRule[1])
		}
		if len(newRule) >= 2 {
			_ = e.roleMgr.AddLink(newRule[0], newRule[1])
		}
	}

	return nil
}

// UpdateGroupingPolicies 批量更新角色分组策略
func (e *Enforcer) UpdateGroupingPolicies(oldRules, newRules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.UpdatePolicies(model.SectionRoleDefinition, "g", oldRules, newRules); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for _, old := range oldRules {
			if len(old) >= 2 {
				e.roleMgr.DeleteLink(old[0], old[1])
			}
		}
		for _, newR := range newRules {
			if len(newR) >= 2 {
				_ = e.roleMgr.AddLink(newR[0], newR[1])
			}
		}
	}

	return nil
}

// ==================== RBAC API ====================

// GetRolesForUser 获取用户的所有角色
func (e *Enforcer) GetRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetRoles(name, domain...)
}

// GetUsersForRole 获取角色的所有用户
func (e *Enforcer) GetUsersForRole(name string, domain ...string) []string {
	return e.roleMgr.GetUsers(name, domain...)
}

// HasRoleForUser 判断用户是否拥有指定角色
func (e *Enforcer) HasRoleForUser(name, roleName string, domain ...string) bool {
	return e.roleMgr.HasLink(name, roleName, domain...)
}

// AddRoleForUser 为用户添加角色（同时写入适配器和通知其他节点）
func (e *Enforcer) AddRoleForUser(user, roleName string, domain ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.roleMgr.AddLink(user, roleName, domain...); err != nil {
		return err
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "g, " + user + ", " + roleName
		if len(domain) > 0 {
			line += ", " + domain[0]
		}
		if err := e.policy.GetAdapter().AddPolicy(line); err != nil {
			e.roleMgr.DeleteLink(user, roleName, domain...)
			return errors.WrapError("auto-save role", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, "g", nil, []string{user, roleName})

	return nil
}

// DeleteRoleForUser 删除用户的角色（同时从适配器删除和通知其他节点）
func (e *Enforcer) DeleteRoleForUser(user, roleName string, domain ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.roleMgr.DeleteLink(user, roleName, domain...)

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "g, " + user + ", " + roleName
		if len(domain) > 0 {
			line += ", " + domain[0]
		}
		if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
			return errors.WrapError("auto-remove role", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", []string{user, roleName}, nil)

	return nil
}

// DeleteRolesForUser 删除用户的所有角色
func (e *Enforcer) DeleteRolesForUser(user string, domain ...string) error {
	roles := e.roleMgr.GetRoles(user, domain...)
	for _, r := range roles {
		e.roleMgr.DeleteLink(user, r, domain...)
	}
	return nil
}

// DeleteUser 删除用户及其所有角色关系
func (e *Enforcer) DeleteUser(user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	roles := e.roleMgr.GetRoles(user)
	for _, r := range roles {
		e.roleMgr.DeleteLink(user, r)
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user)
}

// DeleteRole 删除角色及其所有用户关系
func (e *Enforcer) DeleteRole(roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	users := e.roleMgr.GetUsers(roleName)
	for _, u := range users {
		e.roleMgr.DeleteLink(u, roleName)
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 1, roleName)
}

// GetImplicitRolesForUser 获取用户的隐式角色（包含继承链上的所有角色）
func (e *Enforcer) GetImplicitRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetImplicitRoles(name, domain...)
}

// GetImplicitPermissionsForUser 获取用户的隐式权限（包含继承链上所有角色的权限）
func (e *Enforcer) GetImplicitPermissionsForUser(user string, domain ...string) [][]string {
	roles := e.roleMgr.GetImplicitRoles(user, domain...)
	roles = append(roles, user)

	var permissions [][]string
	seen := make(map[string]bool)

	for _, r := range roles {
		policies := e.policy.GetFilteredPolicy("p", 0, r)
		for _, p := range policies {
			key := strings.Join(p, ",")
			if !seen[key] {
				seen[key] = true
				permissions = append(permissions, p)
			}
		}
	}

	return permissions
}

// GetImplicitUsersForPermission 获取拥有指定权限的所有隐式用户
func (e *Enforcer) GetImplicitUsersForPermission(permission ...string) []string {
	policies := e.policy.GetFilteredPolicy("p", 1, permission...)

	var users []string
	seen := make(map[string]bool)

	for _, p := range policies {
		if len(p) > 0 && !seen[p[0]] {
			seen[p[0]] = true
			users = append(users, p[0])

			implicitUsers := e.roleMgr.GetImplicitUsers(p[0])
			for _, u := range implicitUsers {
				if !seen[u] {
					seen[u] = true
					users = append(users, u)
				}
			}
		}
	}

	return users
}

// GetPermissionsForUser 获取用户的直接权限
func (e *Enforcer) GetPermissionsForUser(user string, domain ...string) [][]string {
	return e.policy.GetFilteredPolicy("p", 0, user)
}

// HasPermissionForUser 判断用户是否拥有指定权限
func (e *Enforcer) HasPermissionForUser(user string, permission ...string) bool {
	return e.policy.HasPolicy("p", append([]string{user}, permission...))
}

// AddPermissionForUser 为用户添加单条权限
// 等价于 AddPolicy(user, permission...)
// 例如：AddPermissionForUser("alice", "data1", "read")
func (e *Enforcer) AddPermissionForUser(user string, permission ...string) error {
	return e.AddPolicy(append([]string{user}, permission...)...)
}

// AddPermissionsForUser 为用户批量添加权限
// permissions 为权限数组，每个元素是一条完整的权限（不含用户名）
// 例如：AddPermissionsForUser("alice", []string{"data1","read"}, []string{"data2","write"})
func (e *Enforcer) AddPermissionsForUser(user string, permissions ...[]string) error {
	var rules [][]string
	for _, perm := range permissions {
		rules = append(rules, append([]string{user}, perm...))
	}
	return e.AddPolicies(rules)
}

// DeletePermissionForUser 删除用户的单条权限
// 等价于 RemovePolicy(user, permission...)
func (e *Enforcer) DeletePermissionForUser(user string, permission ...string) error {
	return e.RemovePolicy(append([]string{user}, permission...)...)
}

// DeletePermissionsForUser 删除用户的所有权限
// 移除 p 段中以 user 为第一字段的所有策略行
func (e *Enforcer) DeletePermissionsForUser(user string) error {
	return e.RemoveFilteredPolicy(0, user)
}

// DeletePermission 删除指定权限（按权限内容匹配，不限定用户）
// 移除 p 段中从第 1 个字段开始匹配 permission 的所有策略行
// 例如：DeletePermission("data1", "read") 会删除所有用户对 data1 的 read 权限
func (e *Enforcer) DeletePermission(permission ...string) error {
	return e.RemoveFilteredPolicy(1, permission...)
}

// ==================== RBAC Domain API ====================
// 以下 API 支持多租户域隔离，domain 参数用于指定租户/平台/地区等维度
// 域隔离原理：角色键格式为 "domain:name"，不同域的角色关系互不影响
//
// 数据权限扩展：
//   除了租户（tenant）维度，还可以通过域机制实现更细粒度的数据权限：
//   - 平台维度：domain="platform:web" / domain="platform:mobile"
//   - 地区维度：domain="region:cn-east" / domain="region:us-west"
//   - 组合维度：domain="tenant1:platform:web:region:cn-east"
//   只需在策略文件中使用对应的域标识即可实现数据权限隔离

// GetUsersForRoleInDomain 获取指定域中拥有某角色的用户列表
// name: 角色名称，domain: 域标识（如 "tenant1"、"platform:web"）
func (e *Enforcer) GetUsersForRoleInDomain(name, domain string) []string {
	return e.roleMgr.GetUsers(name, domain)
}

// GetRolesForUserInDomain 获取指定域中用户的角色列表
func (e *Enforcer) GetRolesForUserInDomain(name, domain string) []string {
	return e.roleMgr.GetRoles(name, domain)
}

// GetPermissionsForUserInDomain 获取指定域中用户的权限列表
// 先获取用户在域中的所有角色，再查找这些角色在域中的策略
func (e *Enforcer) GetPermissionsForUserInDomain(user, domain string) [][]string {
	roles := e.roleMgr.GetRoles(user, domain)
	allSubjects := append([]string{user}, roles...)

	var result [][]string
	for _, subject := range allSubjects {
		policies := e.policy.GetFilteredPolicy("p", 0, subject, domain)
		result = append(result, policies...)
	}
	return result
}

// AddRoleForUserInDomain 在指定域中为用户添加角色
// 等价于在 g 段添加策略：user, roleName, domain
func (e *Enforcer) AddRoleForUserInDomain(user, roleName, domain string) error {
	return e.AddRoleForUser(user, roleName, domain)
}

// DeleteRoleForUserInDomain 在指定域中删除用户的角色
func (e *Enforcer) DeleteRoleForUserInDomain(user, roleName, domain string) error {
	return e.DeleteRoleForUser(user, roleName, domain)
}

// DeleteRolesForUserInDomain 删除指定域中用户的所有角色
func (e *Enforcer) DeleteRolesForUserInDomain(user, domain string) error {
	return e.DeleteRolesForUser(user, domain)
}

// GetAllUsersByDomain 获取指定域中的所有用户
func (e *Enforcer) GetAllUsersByDomain(domain string) []string {
	return e.roleMgr.GetUsers("role", domain)
}

// DeleteAllUsersByDomain 删除指定域中的所有用户角色关系
func (e *Enforcer) DeleteAllUsersByDomain(domain string) error {
	e.roleMgr.DeleteDomain(domain)
	return nil
}

// DeleteDomains 批量删除多个域的角色关系
func (e *Enforcer) DeleteDomains(domains ...string) error {
	for _, d := range domains {
		e.roleMgr.DeleteDomain(d)
	}
	return nil
}

// GetAllDomains 获取所有域列表
func (e *Enforcer) GetAllDomains() []string {
	return e.roleMgr.GetAllDomains()
}

// GetAllRolesByDomain 获取指定域中的所有角色
func (e *Enforcer) GetAllRolesByDomain(domain string) []string {
	return e.roleMgr.GetRoles("role", domain)
}

// ==================== Management API ====================
// 以下 API 提供策略的查询和管理能力，用于管理后台等场景

// GetAllSubjects 获取所有策略主体（p 段第 0 字段去重）
func (e *Enforcer) GetAllSubjects() []string {
	return e.policy.GetAllSubjects()
}

// GetAllNamedSubjects 获取指定策略类型的所有主体（去重）
func (e *Enforcer) GetAllNamedSubjects(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 0 && !seen[p[0]] {
			seen[p[0]] = true
			result = append(result, p[0])
		}
	}
	return result
}

// GetAllObjects 获取所有策略客体（p 段第 1 字段去重）
func (e *Enforcer) GetAllObjects() []string {
	return e.policy.GetAllObjects()
}

// GetAllNamedObjects 获取指定策略类型的所有客体（去重）
func (e *Enforcer) GetAllNamedObjects(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 1 && !seen[p[1]] {
			seen[p[1]] = true
			result = append(result, p[1])
		}
	}
	return result
}

// GetAllActions 获取所有策略动作（p 段第 2 字段去重）
func (e *Enforcer) GetAllActions() []string {
	return e.policy.GetAllActions()
}

// GetAllNamedActions 获取指定策略类型的所有动作（去重）
func (e *Enforcer) GetAllNamedActions(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 2 && !seen[p[2]] {
			seen[p[2]] = true
			result = append(result, p[2])
		}
	}
	return result
}

// GetAllRoles 获取所有角色（g 段第 1 字段去重）
func (e *Enforcer) GetAllRoles() []string {
	return e.policy.GetAllRoles()
}

// GetAllNamedRoles 获取指定策略类型的所有角色（去重）
func (e *Enforcer) GetAllNamedRoles(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 1 && !seen[p[1]] {
			seen[p[1]] = true
			result = append(result, p[1])
		}
	}
	return result
}

// GetAllUsers 获取所有用户列表
func (e *Enforcer) GetAllUsers() []string {
	return e.policy.GetAllUsers()
}

// GetPolicy 获取 p 段的所有策略
func (e *Enforcer) GetPolicy() [][]string {
	return e.policy.GetAllPolicies("p")
}

// GetFilteredPolicy 获取 p 段的过滤策略
// fieldIndex: 起始字段索引，fieldValues: 过滤值
func (e *Enforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy("p", fieldIndex, fieldValues...)
}

// GetNamedPolicy 获取指定策略类型的所有策略
func (e *Enforcer) GetNamedPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

// GetFilteredNamedPolicy 获取指定策略类型的过滤策略
func (e *Enforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

// GetGroupingPolicy 获取 g 段的所有角色分组策略
func (e *Enforcer) GetGroupingPolicy() [][]string {
	return e.policy.GetAllPolicies("g")
}

// GetFilteredGroupingPolicy 获取 g 段的过滤分组策略
func (e *Enforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy("g", fieldIndex, fieldValues...)
}

// GetNamedGroupingPolicy 获取指定策略类型的所有分组策略
func (e *Enforcer) GetNamedGroupingPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

// GetFilteredNamedGroupingPolicy 获取指定策略类型的过滤分组策略
func (e *Enforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

// HasNamedPolicy 判断指定策略类型中是否存在某条策略
func (e *Enforcer) HasNamedPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

// HasGroupingPolicy 判断 g 段中是否存在某条分组策略
func (e *Enforcer) HasGroupingPolicy(params ...string) bool {
	return e.policy.HasPolicy("g", params)
}

// HasNamedGroupingPolicy 判断指定策略类型中是否存在某条分组策略
func (e *Enforcer) HasNamedGroupingPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

// ==================== Self API (without autoNotifyWatcher) ====================
// 以下 API 直接操作策略，不触发自动通知（autoNotifyWatcher）
// 适用于批量操作场景：先通过 SelfXxx 批量修改，最后手动调用通知

// SelfAddPolicy 直接添加策略（不触发通知和自动保存）
func (e *Enforcer) SelfAddPolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicy(sec, ptype, rule)
}

// SelfAddPolicies 批量添加策略（不触发通知，遇到重复策略返回错误）
func (e *Enforcer) SelfAddPolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicies(sec, ptype, rules)
}

// SelfAddPoliciesEx 批量添加策略（不触发通知，跳过重复策略）
func (e *Enforcer) SelfAddPoliciesEx(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(sec, ptype, rules)
}

// SelfRemovePolicy 直接删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicy(sec, ptype, rule)
}

// SelfRemovePolicies 批量删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicies(sec, ptype, rules)
}

// SelfRemoveFilteredPolicy 按条件过滤删除策略（不触发通知）
func (e *Enforcer) SelfRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

// SelfUpdatePolicy 更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicy(sec, ptype, oldRule, newRule)
}

// SelfUpdatePolicies 批量更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicies(sec, ptype, oldRules, newRules)
}

// ==================== Enforcer Control API ====================
// 以下 API 控制执行器的行为开关和状态

// Enable 启用/禁用执行器
// 禁用时所有 Enforce 调用返回错误，状态机切换到 StateDisabled
func (e *Enforcer) Enable(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = enabled
	targetState := mathx.IF(enabled, StateReady, StateDisabled)
	_ = e.stateMachine.TransitionTo(targetState)

	e.logger.InfoKV("Enforcer enabled state changed", "enabled", enabled)
}

// EnableAutoSave 启用/禁用自动保存
// 开启后 AddPolicy/RemovePolicy 等操作会自动持久化到适配器
func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoSave = autoSave
}

// EnableAutoBuildRoleLinks 启用/禁用自动构建角色继承链
// 开启后添加 g 策略时自动更新角色管理器的继承关系
func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuild bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoBuildRoleLinks = autoBuild
}

// EnableAutoNotifyWatcher 启用/禁用自动通知策略变更
// 开启后策略变更会通过 Pub/Sub 广播给其他节点
func (e *Enforcer) EnableAutoNotifyWatcher(autoNotify bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoNotifyWatcher = autoNotify
}

// IsEnabled 检查执行器是否启用
func (e *Enforcer) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// IsAutoSave 检查是否启用自动保存
func (e *Enforcer) IsAutoSave() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.autoSave
}

// IsFiltered 检查策略是否经过过滤加载
func (e *Enforcer) IsFiltered() bool {
	return e.policy.IsFiltered()
}

// GetState 获取执行器当前状态（Ready/Disabled/Error）
func (e *Enforcer) GetState() string {
	return e.stateMachine.CurrentState()
}

// GetModel 获取当前权限模型
func (e *Enforcer) GetModel() *model.Model {
	return e.model
}

// SetModel 设置权限模型（热替换，需重新加载策略）
func (e *Enforcer) SetModel(m *model.Model) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model = m
}

// GetPolicyManager 获取策略管理器
func (e *Enforcer) GetPolicyManager() *policy.Policy {
	return e.policy
}

// GetRoleManager 获取角色管理器
func (e *Enforcer) GetRoleManager() *role.RoleManager {
	return e.roleMgr
}

// SetRoleManager 设置角色管理器（热替换）
func (e *Enforcer) SetRoleManager(rm *role.RoleManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roleMgr = rm
}

// GetAdapter 获取策略适配器
func (e *Enforcer) GetAdapter() policy.Adapter {
	return e.policy.GetAdapter()
}

// SetAdapter 设置策略适配器（热替换）
func (e *Enforcer) SetAdapter(adapter policy.Adapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy.SetAdapter(adapter)
}

// GetBreaker 获取熔断器实例
func (e *Enforcer) GetBreaker() *breaker.Circuit {
	return e.breaker
}

// GetWatcher 获取文件变更监控器
func (e *Enforcer) GetWatcher() *policy.PolicyWatcher {
	return e.watcher
}

// ClearPolicy 清空所有策略和缓存
func (e *Enforcer) ClearPolicy() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model.ClearPolicies()
	e.policy.GetCache().InvalidateAll()
}

// LoadPolicy 从适配器加载策略
// 加载失败时状态机切换到 StateError
// 加载成功后自动构建角色继承链（如果 autoBuildRoleLinks 开启）
func (e *Enforcer) LoadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	return nil
}

// LoadFilteredPolicy 从适配器加载过滤后的策略
// filter 参数格式取决于适配器实现
func (e *Enforcer) LoadFilteredPolicy(filter interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadFilteredPolicy(filter); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	return nil
}

// SavePolicy 将当前策略保存到适配器
func (e *Enforcer) SavePolicy() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy.SavePolicy()
}

// BuildRoleLinks 手动构建角色继承链
// 遍历 g 段策略，将角色关系注入角色管理器
func (e *Enforcer) BuildRoleLinks() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loadRoleLinks()
	return nil
}

// ReloadPolicy 重新加载策略
// 从适配器重新加载策略并重建角色继承链
// 加载失败时状态机切换到 StateError
func (e *Enforcer) ReloadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	e.loadRoleLinks()
	e.logger.InfoKV("Policy reloaded successfully")
	return nil
}

// SetMonitor 设置监控接口（预留扩展）
func (e *Enforcer) SetMonitor(m interface{}) {
	e.monitor = m
}

// ==================== Internal Methods ====================
// 以下为内部方法，不对外暴露

// executeWithBreaker 通过熔断器执行函数
// 当熔断器处于 Open 状态时直接返回 ErrBreakerOpen 错误
// 当函数执行失败时，熔断器会累计失败次数，达到阈值后熔断
func (e *Enforcer) executeWithBreaker(fn func() (bool, error)) (bool, error) {
	var result bool
	var err error

	breakerErr := e.breaker.Execute(func() error {
		result, err = fn()
		return err
	})

	if breakerErr != nil {
		if breakerErr == breaker.ErrOpen {
			return false, errors.NewEnforcerBreakerOpenError(e.breaker.GetStats()["name"].(string))
		}
		return false, breakerErr
	}

	return result, nil
}

// doEnforce 执行权限校验核心逻辑
// 流程：构建请求 → 获取 matcher 表达式 → 匹配策略 → 评估策略效果
// 内置 panic 恢复机制，防止匹配函数异常导致服务崩溃
func (e *Enforcer) doEnforce(ctx context.Context, rvals ...interface{}) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var err error
	defer syncx.RecoverToError(&err, func(r interface{}) {
		e.logger.ErrorKV("Panic recovered in enforce", "panic", fmt.Sprintf("%v", r))
	})

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}

	matcherExpr := e.getMatcherExpression()
	if matcherExpr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, errors.NewPolicyNotFoundError("p")
	}

	mc := &MatchContext{
		Request:   request,
		Policies:  policyAssertion.Policies,
		RoleMgr:   e.roleMgr,
		Assertion: policyAssertion,
	}

	matched, matchedEffects, err := e.matcher.Match(mc, matcherExpr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffectFromResults(matchedEffects)
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

// buildRequest 根据请求参数构建请求映射
// 将 rvals 按顺序映射到 r 段的 token 名称
// 例如：r = sub, obj, act → rvals=["alice","data1","read"] → {r.sub:"alice", r.obj:"data1", r.act:"read"}
func (e *Enforcer) buildRequest(rvals ...interface{}) map[string]interface{} {
	reqAssertion := e.model.GetAssertion(model.SectionRequestDefinition)
	if reqAssertion == nil {
		for key, a := range e.model.GetAssertions() {
			if strings.HasPrefix(key, model.SectionRequestDefinition) {
				reqAssertion = a
				break
			}
		}
	}

	if reqAssertion == nil {
		return nil
	}

	request := make(map[string]interface{})
	for i, token := range reqAssertion.Tokens {
		if i < len(rvals) {
			request[token] = rvals[i]
		}
	}

	return request
}

// getMatcherExpression 获取 m 段的匹配器表达式
// 例如：m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
func (e *Enforcer) getMatcherExpression() string {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionMatchers) {
			return assertion.Value
		}
	}
	return ""
}

// getPolicyAssertion 获取 p 段的策略断言
func (e *Enforcer) getPolicyAssertion() *model.Assertion {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyDefinition) {
			return assertion
		}
	}
	return nil
}

// evaluateEffectFromResults 根据匹配策略的效果列表评估最终结果
// 只评估匹配到的策略效果，而非全部策略
// 例如：e = some(where (p.eft == allow)) → 只要有一条匹配的策略 eft 为 allow 则允许
func (e *Enforcer) evaluateEffectFromResults(matchedEffects []string) (policy.EffectResult, error) {
	effectExpr := ""
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyEffect) {
			effectExpr = assertion.Value
			break
		}
	}

	if effectExpr == "" {
		return policy.EffectAllowResult, nil
	}

	evaluator := policy.NewEffectEvaluator(effectExpr)
	return evaluator.Evaluate(matchedEffects)
}

// evaluateEffect 评估策略效果（基于全部策略，兼容旧接口）
func (e *Enforcer) evaluateEffect() (policy.EffectResult, error) {
	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return policy.EffectDenyResult, nil
	}

	effects := make([]string, len(policyAssertion.Policies))
	for i, p := range policyAssertion.Policies {
		eft := "allow"
		for j, token := range policyAssertion.Tokens {
			if token == "p.eft" && j < len(p) {
				eft = p[j]
			}
		}
		effects[i] = eft
	}

	return e.evaluateEffectFromResults(effects)
}

// loadRoleLinks 从 g 段策略构建角色继承链
// 遍历所有 g 段策略，将角色关系注入角色管理器
// 支持域隔离：g 段策略的第 3 个字段作为 domain 参数
func (e *Enforcer) loadRoleLinks() {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionRoleDefinition) {
			for _, p := range assertion.Policies {
				if len(p) >= 2 {
					domain := make([]string, 0)
					if len(p) > 2 {
						domain = append(domain, p[2])
					}
					if err := e.roleMgr.AddLink(p[0], p[1], domain...); err != nil {
						e.logger.WarnKV("Failed to add role link",
							"name1", p[0], "name2", p[1], "error", err.Error())
					}
				}
			}
		}
	}
}

// handlePolicyChange 处理策略变更事件
// 收到其他节点发布的变更事件后，自动重载策略
func (e *Enforcer) handlePolicyChange(event *policy.ChangeEvent) {
	e.logger.InfoKV("Received policy change event, reloading...",
		"event_type", string(event.Type),
		"source", event.Source,
		"ptype", event.PType,
	)

	if err := e.ReloadPolicy(); err != nil {
		e.logger.ErrorKV("Failed to reload policy after change event",
			"error", err.Error(),
			"event_type", string(event.Type),
		)
		return
	}

	e.logger.InfoKV("Policy reloaded after change event",
		"event_type", string(event.Type),
		"source", event.Source,
	)
}

// notifyPolicyChange 通知策略变更
// 本节点修改策略后调用，通过 Pub/Sub 广播给其他节点
func (e *Enforcer) notifyPolicyChange(eventType policy.ChangeEventType, ptype string, oldPolicy, newPolicy []string) {
	if e.notifier == nil || !e.autoNotifyWatcher {
		return
	}

	event := policy.NewChangeEvent(eventType, ptype, "")
	event.OldPolicy = oldPolicy
	event.NewPolicy = newPolicy

	if err := e.notifier.Publish(context.Background(), event); err != nil {
		e.logger.WarnKV("Failed to publish policy change event",
			"error", err.Error(),
			"event_type", string(eventType),
		)
	}
}

// GetNotifier 获取策略变更通知器
func (e *Enforcer) GetNotifier() policy.PolicyNotifier {
	return e.notifier
}

// SetNotifier 设置策略变更通知器
// 设置后自动订阅变更事件
func (e *Enforcer) SetNotifier(notifier policy.PolicyNotifier) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 关闭旧的通知器
	if e.notifier != nil {
		_ = e.notifier.Close()
	}

	e.notifier = notifier

	// 订阅新的通知器
	if notifier != nil {
		if err := notifier.Subscribe(context.Background(), e.handlePolicyChange); err != nil {
			e.logger.WarnKV("Failed to subscribe policy notifier", "error", err.Error())
			return err
		}
	}

	return nil
}
