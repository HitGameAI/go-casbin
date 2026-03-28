/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\matcher.go
 * @Description: 匹配引擎（基于 go-toolbox）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"fmt"
	"strings"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/safe"
)

type MatchContext struct {
	Request   map[string]interface{}
	Policies  [][]string
	RoleMgr   *role.RoleManager
	Assertion *model.Assertion
}

type MatcherEngine struct {
	logger logger.ILogger
}

func NewMatcherEngine(log logger.ILogger) *MatcherEngine {
	return &MatcherEngine{logger: log}
}

func (me *MatcherEngine) Match(mc *MatchContext, matcherExpr string) (bool, error) {
	if strings.Contains(matcherExpr, "g(") {
		return me.matchWithRole(mc, matcherExpr)
	}

	if strings.Contains(matcherExpr, "eval(") {
		return me.matchWithEval(mc, matcherExpr)
	}

	return me.matchBasic(mc, matcherExpr)
}

func (me *MatcherEngine) matchBasic(mc *MatchContext, matcherExpr string) (bool, error) {
	for _, p := range mc.Policies {
		if me.evaluateExpression(mc.Request, p, mc.Assertion, matcherExpr) {
			return true, nil
		}
	}
	return false, nil
}

func (me *MatcherEngine) matchWithRole(mc *MatchContext, matcherExpr string) (bool, error) {
	for _, p := range mc.Policies {
		if me.evaluateExpression(mc.Request, p, mc.Assertion, matcherExpr) {
			return true, nil
		}
	}
	return false, nil
}

func (me *MatcherEngine) matchWithEval(mc *MatchContext, matcherExpr string) (bool, error) {
	for _, p := range mc.Policies {
		if me.evaluateEvalExpression(mc.Request, p, mc.Assertion, matcherExpr) {
			return true, nil
		}
	}
	return false, nil
}

func (me *MatcherEngine) evaluateExpression(request map[string]interface{}, policyLine []string, assertion *model.Assertion, expr string) bool {
	vars := me.buildVariableMap(request, policyLine, assertion)
	return me.evalSimpleExpr(expr, vars)
}

func (me *MatcherEngine) evaluateEvalExpression(request map[string]interface{}, policyLine []string, assertion *model.Assertion, expr string) bool {
	vars := me.buildVariableMap(request, policyLine, assertion)

	evalExpr := expr
	for key, val := range vars {
		placeholder := "eval(" + key + ")"
		if strings.Contains(evalExpr, placeholder) {
			strVal := fmt.Sprintf("%v", val)
			evalExpr = strings.ReplaceAll(evalExpr, placeholder, strVal)
		}
	}

	return me.evalSimpleExpr(evalExpr, vars)
}

func (me *MatcherEngine) buildVariableMap(request map[string]interface{}, policyLine []string, assertion *model.Assertion) map[string]interface{} {
	vars := make(map[string]interface{})

	for key, val := range request {
		vars[key] = val
	}

	if assertion != nil && len(policyLine) > 0 {
		for i, token := range assertion.Tokens {
			if i < len(policyLine) {
				vars[token] = policyLine[i]
			}
		}
	}

	return vars
}

func (me *MatcherEngine) evalSimpleExpr(expr string, vars map[string]interface{}) bool {
	expr = strings.TrimSpace(expr)

	if expr == "" {
		return false
	}

	if strings.Contains(expr, "&&") {
		parts := strings.Split(expr, "&&")
		for _, part := range parts {
			if !me.evalSimpleExpr(strings.TrimSpace(part), vars) {
				return false
			}
		}
		return true
	}

	if strings.Contains(expr, "||") {
		parts := strings.Split(expr, "||")
		for _, part := range parts {
			if me.evalSimpleExpr(strings.TrimSpace(part), vars) {
				return true
			}
		}
		return false
	}

	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		left := me.resolveValue(strings.TrimSpace(parts[0]), vars)
		right := me.resolveValue(strings.TrimSpace(parts[1]), vars)
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right)
	}

	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		left := me.resolveValue(strings.TrimSpace(parts[0]), vars)
		right := me.resolveValue(strings.TrimSpace(parts[1]), vars)
		return fmt.Sprintf("%v", left) != fmt.Sprintf("%v", right)
	}

	return false
}

func (me *MatcherEngine) resolveValue(token string, vars map[string]interface{}) interface{} {
	if val, ok := vars[token]; ok {
		return val
	}

	if strings.Contains(token, ".") {
		parts := strings.SplitN(token, ".", 2)
		if root, ok := vars[parts[0]]; ok {
			accessor := safe.Safe(root)
			result := accessor.Field(parts[1])
			if result.IsValid() {
				return result.Value()
			}
		}
	}

	return token
}

func (me *MatcherEngine) evaluateRoleFunction(name1, name2 string, roleMgr *role.RoleManager) bool {
	if roleMgr == nil {
		return false
	}
	return roleMgr.HasLink(name1, name2)
}
