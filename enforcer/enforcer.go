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

const (
	StateReady    = "ready"
	StateDisabled = "disabled"
	StateError    = "error"
)

type Enforcer struct {
	mu      sync.RWMutex
	model   *model.Model
	policy  *policy.Policy
	roleMgr *role.RoleManager
	matcher *MatcherEngine
	monitor interface{}
	watcher *policy.PolicyWatcher

	stateMachine *syncx.StateMachine[string]
	breaker      *breaker.Circuit
	retry        *retry.Retry
	idGenerator  idgen.IDGenerator
	logger       logger.ILogger

	customFuncs map[string]BuiltinFunc

	autoSave           bool
	autoBuildRoleLinks bool
	autoNotifyWatcher  bool
	enabled            bool
}

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
	if o.policyPath != "" {
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

func (e *Enforcer) Close() {
	if e.watcher != nil {
		e.watcher.Stop()
	}
	e.logger.InfoMsg("Enforcer closed")
}

// ==================== Enforcer API ====================

func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.EnforceContext(context.Background(), rvals...)
}

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

func (e *Enforcer) EnforceWithMatcher(matcherExpr string, rvals ...interface{}) (bool, error) {
	return e.enforceWithMatcherExpr(matcherExpr, rvals...)
}

func (e *Enforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr("", rvals...)
}

func (e *Enforcer) EnforceExWithMatcher(matcherExpr string, rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr(matcherExpr, rvals...)
}

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

	matched, err := e.matcher.Match(mc, expr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffect()
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

	for _, p := range policyAssertion.Policies {
		if e.matcher.evaluateExpression(request, p, policyAssertion, expr) {
			return true, p, nil
		}
	}

	return false, nil, nil
}

// ==================== Custom Function ====================

func (e *Enforcer) AddFunction(name string, fn BuiltinFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customFuncs[name] = fn
	e.logger.InfoKV("Custom function added", "name", name)
}

func (e *Enforcer) GetFunction(name string) (BuiltinFunc, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	fn, ok := e.customFuncs[name]
	return fn, ok
}

// ==================== Policy Management API ====================

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

	return nil
}

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

	return nil
}

func (e *Enforcer) AddPoliciesEx(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionPolicyDefinition, "p", rules)
}

func (e *Enforcer) AddNamedPolicy(ptype string, params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicy(model.SectionPolicyDefinition, ptype, params)
}

func (e *Enforcer) AddNamedPolicies(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicies(model.SectionPolicyDefinition, ptype, rules)
}

func (e *Enforcer) AddNamedPoliciesEx(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionPolicyDefinition, ptype, rules)
}

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

	return nil
}

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

	return nil
}

func (e *Enforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, "p", fieldIndex, fieldValues...)
}

func (e *Enforcer) RemoveNamedPolicy(ptype string, params ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicy(model.SectionPolicyDefinition, ptype, params)
}

func (e *Enforcer) RemoveNamedPolicies(ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicies(model.SectionPolicyDefinition, ptype, rules)
}

func (e *Enforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, ptype, fieldIndex, fieldValues...)
}

func (e *Enforcer) UpdatePolicy(oldPolicy, newPolicy []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicy(model.SectionPolicyDefinition, "p", oldPolicy, newPolicy)
}

func (e *Enforcer) UpdatePolicies(oldPolicies, newPolicies [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicies(model.SectionPolicyDefinition, "p", oldPolicies, newPolicies)
}

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

// ==================== Grouping Policy API ====================

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

func (e *Enforcer) AddGroupingPoliciesEx(rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(model.SectionRoleDefinition, "g", rules)
}

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

func (e *Enforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", fieldIndex, fieldValues...)
}

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

func (e *Enforcer) GetRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetRoles(name, domain...)
}

func (e *Enforcer) GetUsersForRole(name string, domain ...string) []string {
	return e.roleMgr.GetUsers(name, domain...)
}

func (e *Enforcer) HasRoleForUser(name, roleName string, domain ...string) bool {
	return e.roleMgr.HasLink(name, roleName, domain...)
}

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

	return nil
}

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

	return nil
}

func (e *Enforcer) DeleteRolesForUser(user string, domain ...string) error {
	roles := e.roleMgr.GetRoles(user, domain...)
	for _, r := range roles {
		e.roleMgr.DeleteLink(user, r, domain...)
	}
	return nil
}

func (e *Enforcer) DeleteUser(user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	roles := e.roleMgr.GetRoles(user)
	for _, r := range roles {
		e.roleMgr.DeleteLink(user, r)
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 0, user)
}

func (e *Enforcer) DeleteRole(roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	users := e.roleMgr.GetUsers(roleName)
	for _, u := range users {
		e.roleMgr.DeleteLink(u, roleName)
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, "g", 1, roleName)
}

func (e *Enforcer) GetImplicitRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetImplicitRoles(name, domain...)
}

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

func (e *Enforcer) GetPermissionsForUser(user string, domain ...string) [][]string {
	return e.policy.GetFilteredPolicy("p", 0, user)
}

func (e *Enforcer) HasPermissionForUser(user string, permission ...string) bool {
	return e.policy.HasPolicy("p", append([]string{user}, permission...))
}

func (e *Enforcer) AddPermissionForUser(user string, permission ...string) error {
	return e.AddPolicy(append([]string{user}, permission...)...)
}

func (e *Enforcer) AddPermissionsForUser(user string, permissions ...[]string) error {
	var rules [][]string
	for _, perm := range permissions {
		rules = append(rules, append([]string{user}, perm...))
	}
	return e.AddPolicies(rules)
}

func (e *Enforcer) DeletePermissionForUser(user string, permission ...string) error {
	return e.RemovePolicy(append([]string{user}, permission...)...)
}

func (e *Enforcer) DeletePermissionsForUser(user string) error {
	return e.RemoveFilteredPolicy(0, user)
}

func (e *Enforcer) DeletePermission(permission ...string) error {
	return e.RemoveFilteredPolicy(1, permission...)
}

// ==================== RBAC Domain API ====================

func (e *Enforcer) GetUsersForRoleInDomain(name, domain string) []string {
	return e.roleMgr.GetUsers(name, domain)
}

func (e *Enforcer) GetRolesForUserInDomain(name, domain string) []string {
	return e.roleMgr.GetRoles(name, domain)
}

func (e *Enforcer) GetPermissionsForUserInDomain(user, domain string) [][]string {
	return e.policy.GetFilteredPolicy("p", 0, user, domain)
}

func (e *Enforcer) AddRoleForUserInDomain(user, roleName, domain string) error {
	return e.AddRoleForUser(user, roleName, domain)
}

func (e *Enforcer) DeleteRoleForUserInDomain(user, roleName, domain string) error {
	return e.DeleteRoleForUser(user, roleName, domain)
}

func (e *Enforcer) DeleteRolesForUserInDomain(user, domain string) error {
	return e.DeleteRolesForUser(user, domain)
}

func (e *Enforcer) GetAllUsersByDomain(domain string) []string {
	return e.roleMgr.GetUsers("role", domain)
}

func (e *Enforcer) DeleteAllUsersByDomain(domain string) error {
	e.roleMgr.DeleteDomain(domain)
	return nil
}

func (e *Enforcer) DeleteDomains(domains ...string) error {
	for _, d := range domains {
		e.roleMgr.DeleteDomain(d)
	}
	return nil
}

func (e *Enforcer) GetAllDomains() []string {
	return e.roleMgr.GetAllDomains()
}

func (e *Enforcer) GetAllRolesByDomain(domain string) []string {
	return e.roleMgr.GetRoles("role", domain)
}

// ==================== Management API ====================

func (e *Enforcer) GetAllSubjects() []string {
	return e.policy.GetAllSubjects()
}

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

func (e *Enforcer) GetAllObjects() []string {
	return e.policy.GetAllObjects()
}

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

func (e *Enforcer) GetAllActions() []string {
	return e.policy.GetAllActions()
}

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

func (e *Enforcer) GetAllRoles() []string {
	return e.policy.GetAllRoles()
}

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

func (e *Enforcer) GetAllUsers() []string {
	return e.policy.GetAllUsers()
}

func (e *Enforcer) GetPolicy() [][]string {
	return e.policy.GetAllPolicies("p")
}

func (e *Enforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy("p", fieldIndex, fieldValues...)
}

func (e *Enforcer) GetNamedPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

func (e *Enforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

func (e *Enforcer) GetGroupingPolicy() [][]string {
	return e.policy.GetAllPolicies("g")
}

func (e *Enforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy("g", fieldIndex, fieldValues...)
}

func (e *Enforcer) GetNamedGroupingPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

func (e *Enforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

func (e *Enforcer) HasNamedPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

func (e *Enforcer) HasGroupingPolicy(params ...string) bool {
	return e.policy.HasPolicy("g", params)
}

func (e *Enforcer) HasNamedGroupingPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

// ==================== Self API (without autoNotifyWatcher) ====================

func (e *Enforcer) SelfAddPolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicy(sec, ptype, rule)
}

func (e *Enforcer) SelfAddPolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPolicies(sec, ptype, rules)
}

func (e *Enforcer) SelfAddPoliciesEx(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.AddPoliciesEx(sec, ptype, rules)
}

func (e *Enforcer) SelfRemovePolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicy(sec, ptype, rule)
}

func (e *Enforcer) SelfRemovePolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemovePolicies(sec, ptype, rules)
}

func (e *Enforcer) SelfRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

func (e *Enforcer) SelfUpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicy(sec, ptype, oldRule, newRule)
}

func (e *Enforcer) SelfUpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.UpdatePolicies(sec, ptype, oldRules, newRules)
}

// ==================== Enforcer Control API ====================

func (e *Enforcer) Enable(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = enabled
	targetState := mathx.IF(enabled, StateReady, StateDisabled)
	_ = e.stateMachine.TransitionTo(targetState)

	e.logger.InfoKV("Enforcer enabled state changed", "enabled", enabled)
}

func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoSave = autoSave
}

func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuild bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoBuildRoleLinks = autoBuild
}

func (e *Enforcer) EnableAutoNotifyWatcher(autoNotify bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoNotifyWatcher = autoNotify
}

func (e *Enforcer) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

func (e *Enforcer) IsAutoSave() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.autoSave
}

func (e *Enforcer) IsFiltered() bool {
	return e.policy.IsFiltered()
}

func (e *Enforcer) GetState() string {
	return e.stateMachine.CurrentState()
}

func (e *Enforcer) GetModel() *model.Model {
	return e.model
}

func (e *Enforcer) SetModel(m *model.Model) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model = m
}

func (e *Enforcer) GetPolicyManager() *policy.Policy {
	return e.policy
}

func (e *Enforcer) GetRoleManager() *role.RoleManager {
	return e.roleMgr
}

func (e *Enforcer) SetRoleManager(rm *role.RoleManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roleMgr = rm
}

func (e *Enforcer) GetAdapter() policy.Adapter {
	return e.policy.GetAdapter()
}

func (e *Enforcer) SetAdapter(adapter policy.Adapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy.SetAdapter(adapter)
}

func (e *Enforcer) GetBreaker() *breaker.Circuit {
	return e.breaker
}

func (e *Enforcer) GetWatcher() *policy.PolicyWatcher {
	return e.watcher
}

func (e *Enforcer) ClearPolicy() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model.ClearPolicies()
	e.policy.GetCache().InvalidateAll()
}

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

func (e *Enforcer) SavePolicy() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy.SavePolicy()
}

func (e *Enforcer) BuildRoleLinks() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loadRoleLinks()
	return nil
}

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

func (e *Enforcer) SetMonitor(m interface{}) {
	e.monitor = m
}

// ==================== Internal Methods ====================

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

	matched, err := e.matcher.Match(mc, matcherExpr)
	if err != nil {
		return false, errors.WrapError("matcher execution failed", err)
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffect()
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

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

func (e *Enforcer) getMatcherExpression() string {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionMatchers) {
			return assertion.Value
		}
	}
	return ""
}

func (e *Enforcer) getPolicyAssertion() *model.Assertion {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyDefinition) {
			return assertion
		}
	}
	return nil
}

func (e *Enforcer) evaluateEffect() (policy.EffectResult, error) {
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

	return evaluator.Evaluate(effects)
}

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
