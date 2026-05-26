/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 09:16:22
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

// 策略主体常量
const (
	SubjectAnonymous     = "anonymous"     // 匿名主体：公开接口策略使用
	SubjectAuthenticated = "authenticated" // 已认证主体：认证免鉴权策略使用
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
//   - 公开策略：IsPublicPolicy 检查路径是否允许匿名访问
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

	autoSave           bool       // 是否自动保存策略到适配器（AddPolicy/RemovePolicy 时自动持久化）
	autoBuildRoleLinks bool       // 是否自动构建角色继承链（添加 g 策略时自动更新角色关系）
	autoNotifyWatcher  bool       // 是否自动通知策略变更（含 Pub/Sub 广播到其他节点）
	enabled            bool       // 执行器是否启用（禁用时所有 Enforce 返回 EnforcerDisabledError）
	publicPolicies     [][]string // 公开接口策略（允许匿名访问的路径，不持久化到适配器）
	authSkipPolicies   [][]string // 认证免鉴权策略（需 JWT 但跳过 Casbin 的路径，不持久化到适配器）

	// 性能优化：缓存热路径上重复创建的对象
	effectEvaluator *policy.EffectEvaluator   // 缓存效果评估器（effect 表达式在模型加载后不变）
	extraPolicies   map[string]*PolicySegment // 缓存额外策略段（p2/p3 等，策略变更时重建）
	matcherExpr     string                    // 缓存 matcher 表达式（模型加载后不变）
	requestTokens   []string                  // 缓存请求 token 列表（r 段定义，模型加载后不变）
	shortCircuit    bool                      // 缓存短路优化标志（effect 表达式不变时结果不变）
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
		publicPolicies:     o.publicPolicies,
		authSkipPolicies:   o.authSkipPolicies,
	}

	e.registerBuiltinFunctions()

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

	// 初始化性能缓存：effect 评估器和 matcher 表达式在模型加载后不变
	e.initCachedFields()

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

	// 加载公开接口策略（仅内存，不持久化到适配器）
	if len(o.publicPolicies) > 0 {
		e.publicPolicies = o.publicPolicies
		e.reloadPublicPoliciesUnlocked()
		o.logger.InfoKV("Public policies loaded", "count", len(o.publicPolicies))
	}

	// 加载认证免鉴权策略（仅内存，不持久化到适配器）
	if len(o.authSkipPolicies) > 0 {
		e.authSkipPolicies = o.authSkipPolicies
		e.reloadAuthSkipPoliciesUnlocked()
		o.logger.InfoKV("Auth-skip policies loaded", "count", len(o.authSkipPolicies))
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
// 共享一次读锁，避免每个请求重复获取/释放 RLock
func (e *Enforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i, req := range requests {
		result, err := e.doEnforce(context.Background(), req...)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// BatchEnforceWithMatcher 使用自定义匹配表达式批量执行权限校验
// 共享一次读锁，避免每个请求重复获取/释放 RLock
func (e *Enforcer) BatchEnforceWithMatcher(matcherExpr string, requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i, req := range requests {
		result, err := e.doEnforceWithMatcher(context.Background(), matcherExpr, req...)
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

	return e.doEnforceWithMatcher(context.Background(), matcherExpr, rvals...)
}

// doEnforceWithMatcher 不加锁的 EnforceWithMatcher 内部实现
// 调用方必须已持有 e.mu 读锁
func (e *Enforcer) doEnforceWithMatcher(ctx context.Context, matcherExpr string, rvals ...interface{}) (bool, error) {
	if err := e.validateRequest(rvals); err != nil {
		return false, err
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}

	expr := matcherExpr
	if expr == "" {
		expr = e.matcherExpr
	}
	if expr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, errors.NewPolicyNotFoundError("p")
	}

	mc := &MatchContext{
		Request:       request,
		Policies:      policyAssertion.Policies,
		RoleMgr:       e.roleMgr,
		Assertion:     policyAssertion,
		CustomFuncs:   e.customFuncs,
		ExtraPolicies: e.getExtraPolicies(),
		ShortCircuit:  e.shortCircuit,
		HasEval:       strings.Contains(expr, "eval("),
		HasGFunc:      strings.Contains(expr, "g("),
	}

	matched, matchedEffects, err := e.matcher.Match(mc, expr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffectFromResultsCached(matchedEffects)
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

	if err := e.validateRequest(rvals); err != nil {
		return false, nil, err
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, nil, errors.NewModelInvalidError("invalid request parameters")
	}

	expr := matcherExpr
	if expr == "" {
		expr = e.matcherExpr
	}
	if expr == "" {
		return false, nil, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, nil, errors.NewPolicyNotFoundError("p")
	}

	mc := &MatchContext{
		Request:       request,
		Policies:      policyAssertion.Policies,
		RoleMgr:       e.roleMgr,
		Assertion:     policyAssertion,
		CustomFuncs:   e.customFuncs,
		ExtraPolicies: e.getExtraPolicies(),
		ShortCircuit:  e.shortCircuit,
		HasEval:       strings.Contains(expr, "eval("),
		HasGFunc:      strings.Contains(expr, "g("),
	}

	matched, matchedEffects, err := e.matcher.Match(mc, expr)
	if err != nil {
		return false, nil, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil, nil
	}

	var matchedPolicy []string
	if len(matchedEffects) > 0 {
		matchedPolicy = matchedEffects
	}
	return true, matchedPolicy, nil
}

// ==================== Custom Function ====================

// ==================== 自定义函数 API ====================

func (e *Enforcer) registerBuiltinFunctions() {
	builtins := map[string]BuiltinFunc{
		"keyMatch":   KeyMatchFunc,
		"keyMatch2":  KeyMatch2Func,
		"keyMatch3":  KeyMatch3Func,
		"regexMatch": RegexMatchFunc,
		"ipMatch":    IPMatchFunc,
		"globMatch":  GlobMatchFunc,
	}
	for name, fn := range builtins {
		e.customFuncs[name] = fn
	}
}

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

	if err := e.validatePolicyRule(model.SectionPolicyDefinition, "p", params); err != nil {
		return err
	}

	// Policy 层已统一处理内存写入和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.AddPolicy(model.SectionPolicyDefinition, "p", params); err != nil {
		return err
	}

	e.invalidateExtraPoliciesCache()
	e.notifyPolicyChange(policy.EventTypePolicyAdded, "p", nil, params)

	return nil
}

// AddPolicies 批量添加策略规则
func (e *Enforcer) AddPolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range rules {
		if err := e.validatePolicyRule(model.SectionPolicyDefinition, "p", rule); err != nil {
			return err
		}
	}

	// Policy 层已统一处理内存写入和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.AddPolicies(model.SectionPolicyDefinition, "p", rules); err != nil {
		return err
	}

	e.invalidateExtraPoliciesCache()
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

	// Policy 层已统一处理内存写入和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.AddPolicy(model.SectionPolicyDefinition, ptype, params); err != nil {
		return err
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, ptype, nil, params)
	return nil
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

	// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.RemovePolicy(model.SectionPolicyDefinition, "p", params); err != nil {
		return err
	}

	e.invalidateExtraPoliciesCache()
	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", params, nil)

	return nil
}

// RemovePolicies 批量删除策略规则
func (e *Enforcer) RemovePolicies(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.RemovePolicies(model.SectionPolicyDefinition, "p", rules); err != nil {
		return err
	}

	e.invalidateExtraPoliciesCache()
	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", nil, nil)

	return nil
}

// RemoveFilteredPolicy 按字段过滤删除策略规则
// fieldIndex: 起始字段索引，fieldValues: 过滤字段值
func (e *Enforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", fieldIndex, fieldValues...)
}

// RemoveNamedPolicy 删除指定类型的策略规则
func (e *Enforcer) RemoveNamedPolicy(ptype string, params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
	if err := e.policy.RemovePolicy(model.SectionPolicyDefinition, ptype, params); err != nil {
		return err
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, ptype, params, nil)
	return nil
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
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicy(model.SectionPolicyDefinition, "p", oldPolicy, newPolicy)
}

// UpdatePolicies 批量更新策略规则
func (e *Enforcer) UpdatePolicies(oldPolicies, newPolicies [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicies(model.SectionPolicyDefinition, "p", oldPolicies, newPolicies)
}

// UpdateFilteredPolicies 按过滤条件更新策略规则
func (e *Enforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range newPolicies {
		if err := e.validatePolicyRule(model.SectionPolicyDefinition, "p", rule); err != nil {
			return err
		}
	}

	e.invalidateExtraPoliciesCache()
	return e.policy.UpdateFilteredPolicies(model.SectionPolicyDefinition, "p", newPolicies, fieldIndex, fieldValues...)
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
		domain := make([]string, 0)
		if len(params) >= 3 {
			domain = append(domain, params[2])
		}
		if err := e.roleMgr.AddLink(params[0], params[1], domain...); err != nil {
			return err
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, "g", nil, params)

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
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				_ = e.roleMgr.AddLink(rule[0], rule[1], domain...)
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyAdded, "g", nil, nil)

	return nil
}

// AddGroupingPoliciesEx 批量添加角色分组策略（忽略已存在的规则）
func (e *Enforcer) AddGroupingPoliciesEx(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionRoleDefinition, "g", rules)
}

// RemoveGroupingPolicy 删除角色分组策略
// 同时更新角色继承链、从适配器删除和通知其他节点
func (e *Enforcer) RemoveGroupingPolicy(params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.RemovePolicy(model.SectionRoleDefinition, "g", params); err != nil {
		return err
	}

	if len(params) >= 2 && e.autoBuildRoleLinks {
		domain := make([]string, 0)
		if len(params) >= 3 {
			domain = append(domain, params[2])
		}
		e.roleMgr.DeleteLink(params[0], params[1], domain...)
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		line := "g, " + strings.Join(params, ", ")
		if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
			return errors.WrapError("auto-remove grouping policy", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", params, nil)

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
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
			}
		}
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		if ba, ok := e.policy.GetAdapter().(policy.BatchAdapter); ok {
			var lines []string
			for _, rule := range rules {
				lines = append(lines, "g, "+strings.Join(rule, ", "))
			}
			if err := ba.RemovePolicies(lines); err != nil {
				return errors.WrapError("auto-remove grouping policies", err)
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

	return nil
}

// RemoveFilteredGroupingPolicy 按字段过滤删除角色分组策略
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	removed := e.policy.GetFilteredPolicy("g", fieldIndex, fieldValues...)

	if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", fieldIndex, fieldValues...); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for _, rule := range removed {
			if len(rule) >= 2 {
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

	return nil
}

// DeleteRoleAssignments 删除指定角色的所有分配关系
// 删除 g 段中第二列（角色列）匹配 roleName 的所有记录
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) DeleteRoleAssignments(roleName string) error {
	return e.RemoveFilteredGroupingPolicy(1, roleName)
}

// ClearAllPolicies 清理所有策略和角色关系
// 用于租户删除等场景，彻底清空 enforcer 中的 p 段和 g 段数据
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) ClearAllPolicies() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.model.ClearPolicies()
	e.roleMgr.Clear()

	if e.autoSave && e.policy.GetAdapter() != nil {
		if err := e.policy.GetAdapter().SavePolicy(nil); err != nil {
			return errors.WrapError("clear all policies", err)
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", nil, nil)
	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

	return nil
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
// 同时清理 g 段策略、适配器持久化和分布式通知
func (e *Enforcer) DeleteRolesForUser(user string, domain ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	roles := e.roleMgr.GetRoles(user, domain...)
	if len(roles) == 0 {
		return nil
	}

	for _, r := range roles {
		e.roleMgr.DeleteLink(user, r, domain...)
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user); err != nil {
			e.logger.WarnKV("Failed to remove filtered grouping policy", "user", user, "error", err.Error())
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", []string{user}, nil)

	return nil
}

// DeleteUser 删除用户及其所有角色关系
func (e *Enforcer) DeleteUser(user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	existingGrouping := e.policy.GetFilteredPolicy("g", 0, user)
	for _, rule := range existingGrouping {
		if len(rule) >= 2 {
			domain := make([]string, 0)
			if len(rule) >= 3 {
				domain = append(domain, rule[2])
			}
			e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
		}
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user)
}

// DeleteRole 删除角色及其所有用户关系
func (e *Enforcer) DeleteRole(roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	existingGrouping := e.policy.GetFilteredPolicy("g", 1, roleName)
	for _, rule := range existingGrouping {
		if len(rule) >= 2 {
			domain := make([]string, 0)
			if len(rule) >= 3 {
				domain = append(domain, rule[2])
			}
			e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
		}
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
// 同时清理 g 段策略、适配器持久化和分布式通知
func (e *Enforcer) DeleteAllUsersByDomain(domain string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.roleMgr.DeleteDomain(domain)

	if e.autoSave && e.policy.GetAdapter() != nil {
		if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 2, domain); err != nil {
			e.logger.WarnKV("Failed to remove filtered grouping policy by domain", "domain", domain, "error", err.Error())
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

	return nil
}

// DeleteDomains 批量删除多个域的角色关系
// 同时清理 g 段策略、适配器持久化和分布式通知
func (e *Enforcer) DeleteDomains(domains ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, d := range domains {
		e.roleMgr.DeleteDomain(d)
	}

	if e.autoSave && e.policy.GetAdapter() != nil {
		for _, d := range domains {
			if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 2, d); err != nil {
				e.logger.WarnKV("Failed to remove filtered grouping policy by domain", "domain", d, "error", err.Error())
			}
		}
	}

	e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

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

// ==================== Transactional API ====================
// 以下 API 提供事务支持，确保内存模型、角色管理器和适配器的一致性
// 如果适配器实现了 TransactionalAdapter 接口，操作会在数据库事务中执行
// 否则回退到非事务模式，但仍保证内存状态的一致性
//
// 注意：事务方法内部直接操作内存模型和角色管理器，不调用已加锁的公开方法
// 所有事务方法自行管理锁，避免死锁

// ExecuteInTransaction 在事务中执行批量操作
// 调用方需确保 fn 内部不会尝试获取 enforcer 锁
// 适配器支持事务时，所有操作在同一个数据库事务中执行
func (e *Enforcer) ExecuteInTransaction(ctx context.Context, fn func() error) error {
	if ta, ok := e.policy.GetAdapter().(policy.TransactionalAdapter); ok {
		return ta.ExecuteInTransaction(ctx, func(txAdapter policy.Adapter) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			prevAdapter := e.policy.GetAdapter()
			e.policy.SetAdapter(txAdapter)
			defer e.policy.SetAdapter(prevAdapter)
			return fn()
		})
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return fn()
}

// TransactionalSyncUserRoles 在事务中同步用户角色
// 先删除用户所有旧角色（含 g 段策略和适配器），再批量添加新角色
// 适用于用户角色绑定变更场景，确保角色替换的原子性
// groupingRules 每个元素格式为 [user, roleName, domain]
func (e *Enforcer) TransactionalSyncUserRoles(ctx context.Context, user string, groupingRules [][]string) error {
	return e.ExecuteInTransaction(ctx, func() error {
		existingGrouping := e.policy.GetFilteredPolicy("g", 0, user)
		if len(existingGrouping) > 0 {
			for _, rule := range existingGrouping {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
				}
			}
			if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user); err != nil {
				return err
			}
		}

		if len(groupingRules) > 0 {
			if err := e.policy.AddPolicies(model.SectionRoleDefinition, "g", groupingRules); err != nil {
				return err
			}

			if e.autoBuildRoleLinks {
				for _, rule := range groupingRules {
					if len(rule) >= 2 {
						domain := make([]string, 0)
						if len(rule) >= 3 {
							domain = append(domain, rule[2])
						}
						_ = e.roleMgr.AddLink(rule[0], rule[1], domain...)
					}
				}
			}

		}

		e.notifyPolicyChange(policy.EventTypePolicyAdded, "g", nil, nil)

		return nil
	})
}

// TransactionalDeleteUser 在事务中删除用户及其所有角色关系和权限
// 同时清理 p 段策略、g 段策略、角色管理器和适配器
func (e *Enforcer) TransactionalDeleteUser(ctx context.Context, user string) error {
	return e.ExecuteInTransaction(ctx, func() error {
		_ = e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", 0, user)

		existingGrouping := e.policy.GetFilteredPolicy("g", 0, user)
		for _, rule := range existingGrouping {
			if len(rule) >= 2 {
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
			}
		}
		_ = e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user)

		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", nil, nil)
		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

		return nil
	})
}

// TransactionalDeleteRole 在事务中删除角色及其所有关系
// 同时清理 g 段策略、p 段策略、角色管理器和适配器
func (e *Enforcer) TransactionalDeleteRole(ctx context.Context, roleName string) error {
	return e.ExecuteInTransaction(ctx, func() error {
		users := e.roleMgr.GetUsers(roleName)
		for _, u := range users {
			e.roleMgr.DeleteLink(u, roleName)
		}

		_ = e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 1, roleName)
		_ = e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", 0, roleName)

		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "p", nil, nil)
		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "g", nil, nil)

		return nil
	})
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

// HasPolicy 判断 p 段中是否存在某条策略
func (e *Enforcer) HasPolicy(params ...string) bool {
	return e.policy.HasPolicy("p", params)
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
	if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
		return err
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPolicy(sec, ptype, rule)
}

// SelfAddPolicies 批量添加策略（不触发通知，遇到重复策略返回错误）
func (e *Enforcer) SelfAddPolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rule := range rules {
		if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
			return err
		}
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPolicies(sec, ptype, rules)
}

// SelfAddPoliciesEx 批量添加策略（不触发通知，跳过重复策略）
func (e *Enforcer) SelfAddPoliciesEx(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rule := range rules {
		if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
			return err
		}
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPoliciesEx(sec, ptype, rules)
}

// SelfRemovePolicy 直接删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemovePolicy(sec, ptype, rule)
}

// SelfRemovePolicies 批量删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemovePolicies(sec, ptype, rules)
}

// SelfRemoveFilteredPolicy 按条件过滤删除策略（不触发通知）
func (e *Enforcer) SelfRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

// SelfUpdatePolicy 更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicy(sec, ptype, oldRule, newRule)
}

// SelfUpdatePolicies 批量更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicies(sec, ptype, oldRules, newRules)
}

// ==================== Public Policy API ====================
// 公开接口策略：允许匿名用户访问的路径，在启动时从代码加载，不持久化到适配器

// IsPublicPolicy 检查指定路径和方法是否为公开接口
// 通过 Enforce 检查 anonymous 主体是否有权限访问
// 适用于 Gateway 的 Authorities 方法：公开接口无需 JWT 验证直接放行
//
// 参数格式取决于模型定义：
//   - RBAC: IsPublicPolicy("/v1/login", "POST")
//   - RBAC Domain: IsPublicPolicy("tenant::x", "/v1/login", "POST")
func (e *Enforcer) IsPublicPolicy(rvals ...interface{}) (bool, error) {
	// 将 anonymous 作为主体插入到请求参数的最前面
	requestParams := append([]interface{}{SubjectAnonymous}, rvals...)
	return e.Enforce(requestParams...)
}

// GetPublicPolicies 获取当前配置的公开策略列表
func (e *Enforcer) GetPublicPolicies() [][]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([][]string, len(e.publicPolicies))
	copy(result, e.publicPolicies)
	return result
}

// IsAuthSkipPolicy 检查指定路径和方法是否为认证免鉴权接口
// 通过 Enforce 检查 authenticated 主体是否有权限访问
// 适用于 Gateway 的 Authorities 方法：认证免鉴权接口需要 JWT 验证但跳过 Casbin 权限校验
//
// 参数格式取决于模型定义：
//   - RBAC: IsAuthSkipPolicy("/v1/auth/user-info", "GET")
//   - RBAC Domain: IsAuthSkipPolicy("tenant::x", "/v1/auth/user-info", "GET")
func (e *Enforcer) IsAuthSkipPolicy(rvals ...interface{}) (bool, error) {
	// 将 authenticated 作为主体插入到请求参数的最前面
	requestParams := append([]interface{}{SubjectAuthenticated}, rvals...)
	return e.Enforce(requestParams...)
}

// GetAuthSkipPolicies 获取当前配置的认证免鉴权策略列表
func (e *Enforcer) GetAuthSkipPolicies() [][]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([][]string, len(e.authSkipPolicies))
	copy(result, e.authSkipPolicies)
	return result
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
	// 同步 Policy 层的 autoSave，确保策略操作时正确控制适配器持久化
	e.policy.SetAutoSave(autoSave)
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
// 公开策略会在适配器策略加载后自动重新注入
func (e *Enforcer) LoadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	// 重新加载公开策略（仅内存，不持久化）
	// 直接调用内部方法，因为外层已持有锁
	e.reloadPublicPoliciesUnlocked()

	// 重新加载认证免鉴权策略（仅内存，不持久化）
	e.reloadAuthSkipPoliciesUnlocked()

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

	// 重新加载公开策略（仅内存，不持久化）
	// 直接调用内部方法，因为外层已持有锁
	e.reloadPublicPoliciesUnlocked()

	// 重新加载认证免鉴权策略（仅内存，不持久化）
	e.reloadAuthSkipPoliciesUnlocked()

	e.loadRoleLinks()

	// 策略重载后重建缓存
	e.initCachedFields()

	e.logger.InfoKV("Policy reloaded successfully")
	return nil
}

// SetMonitor 设置监控接口（预留扩展）
func (e *Enforcer) SetMonitor(m interface{}) {
	e.monitor = m
}

// ==================== Internal Methods ====================
// 以下为内部方法，不对外暴露

// reloadPublicPoliciesUnlocked 重新加载公开策略（无锁版本）
// 调用方必须已持有 e.mu 锁
// 临时移除适配器，防止公开策略被写入持久化存储
func (e *Enforcer) reloadPublicPoliciesUnlocked() {
	if len(e.publicPolicies) == 0 {
		return
	}
	// 临时移除适配器，确保公开策略仅添加到模型内存，不持久化
	prevAdapter := e.policy.GetAdapter()
	e.policy.SetAdapter(nil)
	if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, "p", e.publicPolicies); err != nil {
		e.logger.WarnKV("Failed to reload public policies", "error", err.Error())
	}
	e.policy.SetAdapter(prevAdapter)
}

// reloadAuthSkipPoliciesUnlocked 重新加载认证免鉴权策略（无锁版本）
// 调用方必须已持有 e.mu 锁
// 临时移除适配器，防止认证免鉴权策略被写入持久化存储
func (e *Enforcer) reloadAuthSkipPoliciesUnlocked() {
	if len(e.authSkipPolicies) == 0 {
		return
	}
	// 临时移除适配器，确保认证免鉴权策略仅添加到模型内存，不持久化
	prevAdapter := e.policy.GetAdapter()
	e.policy.SetAdapter(nil)
	if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, "p", e.authSkipPolicies); err != nil {
		e.logger.WarnKV("Failed to reload auth-skip policies", "error", err.Error())
	}
	e.policy.SetAdapter(prevAdapter)
}

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
// 流程：校验请求参数 → 构建请求 → 获取 matcher 表达式 → 匹配策略 → 评估策略效果
// 内置 panic 恢复机制，防止匹配函数异常导致服务崩溃
func (e *Enforcer) doEnforce(ctx context.Context, rvals ...interface{}) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var err error
	defer syncx.RecoverToError(&err, func(r interface{}) {
		e.logger.ErrorKV("Panic recovered in enforce", "panic", fmt.Sprintf("%v", r))
	})

	// 安全校验：请求参数不能为空，且必须与模型 r 段定义的字段数量匹配
	if err := e.validateRequest(rvals); err != nil {
		return false, err
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}

	// 使用缓存的 matcher 表达式，避免每次遍历 model assertions
	matcherExpr := e.matcherExpr
	if matcherExpr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return false, errors.NewPolicyNotFoundError("p")
	}

	mc := &MatchContext{
		Request:       request,
		Policies:      policyAssertion.Policies,
		RoleMgr:       e.roleMgr,
		Assertion:     policyAssertion,
		CustomFuncs:   e.customFuncs,
		ExtraPolicies: e.getExtraPolicies(),                   // 使用缓存的 extraPolicies
		ShortCircuit:  e.shortCircuit,                         // 短路优化：some(where(p.eft==allow)) 模式下匹配到即返回
		HasEval:       strings.Contains(matcherExpr, "eval("), // 预计算，避免每条策略重复扫描
		HasGFunc:      strings.Contains(matcherExpr, "g("),    // 预计算，避免每条策略重复扫描
	}

	matched, matchedEffects, err := e.matcher.Match(mc, matcherExpr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	// 使用缓存的 effect 评估器，避免每次创建新对象
	effectResult, err := e.evaluateEffectFromResultsCached(matchedEffects)
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

// initCachedFields 初始化性能缓存字段
// effect 评估器和 matcher 表达式在模型加载后不会变化，缓存后避免每次 Enforce 重复创建
// extraPolicies 在策略变更时需要重建，通过 invalidateExtraPoliciesCache 标记
func (e *Enforcer) initCachedFields() {
	// 缓存 matcher 表达式
	e.matcherExpr = e.getMatcherExpression()

	// 缓存 request tokens（r 段定义）
	e.requestTokens = e.getRequestTokens()

	// 缓存 effect 评估器
	effectExpr := ""
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyEffect) {
			effectExpr = assertion.Value
			break
		}
	}
	if effectExpr != "" {
		e.effectEvaluator = policy.NewEffectEvaluator(effectExpr)
	}

	// 缓存短路优化标志
	e.shortCircuit = e.computeShortCircuit()

	// 初始化 extraPolicies 缓存
	e.extraPolicies = e.buildExtraPolicies("p")
}

// invalidateExtraPoliciesCache 使 extraPolicies 缓存失效
// 在策略增删改时调用，下次 Enforce 时会重建
func (e *Enforcer) invalidateExtraPoliciesCache() {
	e.extraPolicies = nil
}

// getExtraPolicies 获取 extraPolicies（带懒加载缓存）
func (e *Enforcer) getExtraPolicies() map[string]*PolicySegment {
	if e.extraPolicies == nil {
		e.extraPolicies = e.buildExtraPolicies("p")
	}
	return e.extraPolicies
}

// validateRequest 校验 Enforce 请求参数
// 使用缓存的 requestTokens 避免每次遍历 model assertions
func (e *Enforcer) validateRequest(rvals []interface{}) error {
	if len(rvals) == 0 {
		return errors.NewEnforcerInvalidRequestError("no parameters provided")
	}

	// 使用缓存的 requestTokens，避免每次遍历 model
	if tokens := e.requestTokens; tokens != nil && len(rvals) != len(tokens) {
		return errors.NewEnforcerInvalidRequestError(
			fmt.Sprintf("expected %d parameters, got %d", len(tokens), len(rvals)))
	}

	// 校验字符串参数不能为空（空 sub/obj/act 会导致误判）
	for i, val := range rvals {
		if s, ok := val.(string); ok && strings.TrimSpace(s) == "" {
			return errors.NewEnforcerInvalidRequestError(
				fmt.Sprintf("parameter at index %d is empty string", i))
		}
	}

	return nil
}

// computeShortCircuit 计算是否允许短路优化
// 当 effect 表达式为 some(where(p.eft==allow)) 模式时，匹配到 allow 即可返回
func (e *Enforcer) computeShortCircuit() bool {
	if e.effectEvaluator == nil {
		return false
	}
	expr := strings.ToLower(strings.TrimSpace(e.effectEvaluator.GetExpression()))
	return strings.Contains(expr, "some(where") && strings.Contains(expr, "allow") &&
		!strings.Contains(expr, "!some") && !strings.Contains(expr, "deny")
}

// validatePolicyRule 校验策略规则
// 检查：规则字段数量必须与模型 p 段定义匹配、字段值不能为空
// 防止无效策略规则导致匹配异常
func (e *Enforcer) validatePolicyRule(sec, ptype string, rule []string) error {
	if len(rule) == 0 {
		return errors.NewPolicyRuleInvalidError("empty policy rule")
	}

	// 获取 p 段定义的 token 数量
	policyAssertion := e.model.GetAssertion(sec)
	if policyAssertion == nil {
		for key, a := range e.model.GetAssertions() {
			if strings.HasPrefix(key, sec) {
				policyAssertion = a
				break
			}
		}
	}

	if policyAssertion != nil {
		expectedLen := len(policyAssertion.Tokens)
		if ptype != "p" && ptype != "" {
			// 对于 g 段等其他策略段，不强制校验字段数量
			expectedLen = -1
		}
		if expectedLen > 0 && len(rule) != expectedLen {
			return errors.NewPolicyRuleInvalidError(
				fmt.Sprintf("expected %d fields for %s, got %d", expectedLen, ptype, len(rule)))
		}
	}

	// 校验字段值不能为空
	for i, field := range rule {
		if field == "" {
			return errors.NewPolicyRuleInvalidError(
				fmt.Sprintf("field at index %d is empty", i))
		}
	}

	return nil
}

// buildRequest 根据请求参数构建请求映射
// 使用缓存的 requestTokens 避免每次遍历 model assertions
func (e *Enforcer) buildRequest(rvals ...interface{}) map[string]interface{} {
	tokens := e.requestTokens
	if tokens == nil {
		return nil
	}

	request := make(map[string]interface{}, len(tokens))
	for i, token := range tokens {
		if i < len(rvals) {
			request[token] = normalizeRequestValue(token, rvals[i])
		}
	}

	return request
}

// normalizeRequestValue 规范请求参数值，根据 token 类型进行转换
func normalizeRequestValue(token string, value interface{}) interface{} {
	s, ok := value.(string)
	if !ok {
		return value
	}
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(token, ".obj"):
		return normalizeKeyMatchPath(s, false)
	case strings.HasSuffix(token, ".act"):
		return normalizeHTTPAction(s)
	default:
		return s
	}
}

// normalizeHTTPAction 规范 HTTP 动作，确保为大写
// 例如：GET → GET
// 例如：post → POST
// 例如：put → PUT
// 例如：PATCH → PATCH
// 例如：delete → DELETE
// 例如：head → HEAD
// 例如：options → OPTIONS
// 例如：connect → CONNECT
// 例如：trace → TRACE
// 例如：其他 → 其他
func normalizeHTTPAction(action string) string {
	switch strings.ToUpper(action) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return strings.ToUpper(action)
	default:
		return action
	}
}

// getRequestTokens 获取 r 段的 token 列表
func (e *Enforcer) getRequestTokens() []string {
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
	return reqAssertion.Tokens
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
	// 精确匹配 key="p"，避免匹配到 p2、p3 等额外策略段
	if assertion, ok := e.model.GetAssertions()["p"]; ok {
		return assertion
	}
	// 回退：遍历查找第一个策略段
	for key, assertion := range e.model.GetAssertions() {
		if key == model.SectionPolicyDefinition {
			return assertion
		}
	}
	return nil
}

// buildExtraPolicies 构建额外的策略段（排除指定策略）
func (e *Enforcer) buildExtraPolicies(excludeKey string) map[string]*PolicySegment {
	extra := make(map[string]*PolicySegment)
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyDefinition) && key != excludeKey {
			extra[key] = &PolicySegment{
				Policies:  assertion.Policies,
				Assertion: assertion,
			}
		}
	}
	return extra
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

// evaluateEffectFromResultsCached 使用缓存的 EffectEvaluator 评估策略效果
// 避免每次 Enforce 都遍历 model assertions 和创建新的 EffectEvaluator
func (e *Enforcer) evaluateEffectFromResultsCached(matchedEffects []string) (policy.EffectResult, error) {
	if e.effectEvaluator == nil {
		// 降级到原始方法（理论上不会发生，因为 initCachedFields 会初始化）
		return e.evaluateEffectFromResults(matchedEffects)
	}
	return e.effectEvaluator.Evaluate(matchedEffects)
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
