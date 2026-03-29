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
	"regexp"
	"strings"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/safe"
)

// MatchContext 匹配上下文
// 封装一次匹配操作所需的所有数据
type MatchContext struct {
	Request   map[string]interface{} // 请求参数（r 段的键值对，如 r.sub="alice"）
	Policies  [][]string             // 策略列表（p 段的所有策略行）
	RoleMgr   *role.RoleManager      // 角色管理器（用于 g() 函数的角色继承判断）
	Assertion *model.Assertion       // 策略断言（包含字段名映射，如 p.sub/p.obj/p.act）
}

// MatcherEngine 匹配器引擎
// 负责将请求与策略进行匹配，支持三种匹配模式：
//   - 基本匹配：ACL 模式，直接比较 r.sub == p.sub
//   - 角色匹配：RBAC 模式，通过 g(r.sub, p.sub) 判断角色继承
//   - 表达式求值：ABAC 规则模式，通过 eval(p.sub_rule) 动态执行条件表达式
type MatcherEngine struct {
	logger logger.ILogger
}

// NewMatcherEngine 创建匹配器引擎
func NewMatcherEngine(log logger.ILogger) *MatcherEngine {
	return &MatcherEngine{logger: log}
}

// gFuncRegex 匹配 g() 函数调用，如 g(r.sub, p.sub) 或 g(r.sub, p.sub, r.dom)
var gFuncRegex = regexp.MustCompile(`g\(([^,]+),\s*([^,)]+)(?:,\s*([^,)]+))?\)`)

// Match 执行匹配，返回是否匹配以及匹配策略的效果列表
// 核心匹配流程：
//   - 如果有策略，遍历每条策略评估 matcher 表达式
//   - 如果没有策略（纯 ABAC 属性匹配），直接用请求参数评估 matcher
func (me *MatcherEngine) Match(mc *MatchContext, matcherExpr string) (bool, []string, error) {
	matchedEffects := make([]string, 0)

	if len(mc.Policies) == 0 {
		vars := me.buildVariableMap(mc.Request, nil, nil)
		expr := matcherExpr
		if strings.Contains(expr, "eval(") {
			expr = me.expandEval(expr, vars)
		}
		if me.evalExpr(expr, vars, mc.RoleMgr) {
			return true, []string{"allow"}, nil
		}
		return false, nil, nil
	}

	for _, p := range mc.Policies {
		vars := me.buildVariableMap(mc.Request, p, mc.Assertion)

		expr := matcherExpr

		if strings.Contains(expr, "eval(") {
			expr = me.expandEval(expr, vars)
		}

		if me.evalExpr(expr, vars, mc.RoleMgr) {
			eft := me.extractEffect(p, mc.Assertion)
			matchedEffects = append(matchedEffects, eft)
		}
	}

	if len(matchedEffects) > 0 {
		return true, matchedEffects, nil
	}
	return false, nil, nil
}

// expandEval 将 eval(p.sub_rule) 替换为策略中对应的条件表达式值
// 例如：eval(p.sub_rule) → r.sub == "alice"
func (me *MatcherEngine) expandEval(expr string, vars map[string]interface{}) string {
	// 匹配 eval(xxx) 模式
	evalRegex := regexp.MustCompile(`eval\(([^)]+)\)`)
	return evalRegex.ReplaceAllStringFunc(expr, func(match string) string {
		// 提取括号内的变量名
		inner := evalRegex.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		varName := strings.TrimSpace(inner[1])
		if val, ok := vars[varName]; ok {
			return fmt.Sprintf("%v", val)
		}
		return match
	})
}

// extractEffect 从策略行中提取 eft（效果）字段
// 如果策略定义中包含 p.eft 字段，则取对应值；否则默认为 "allow"
func (me *MatcherEngine) extractEffect(policyLine []string, assertion *model.Assertion) string {
	if assertion == nil {
		return "allow"
	}
	for i, token := range assertion.Tokens {
		if token == "p.eft" && i < len(policyLine) {
			return policyLine[i]
		}
	}
	return "allow"
}

// evalExpr 评估一个完整的 matcher 表达式
// 支持 &&、||、==、!=、g() 函数调用
func (me *MatcherEngine) evalExpr(expr string, vars map[string]interface{}, roleMgr *role.RoleManager) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}

	// 处理 && （逻辑与）— 需要考虑括号嵌套
	if topAnd := me.findTopLevelOp(expr, "&&"); topAnd >= 0 {
		left := expr[:topAnd]
		right := expr[topAnd+2:]
		return me.evalExpr(left, vars, roleMgr) && me.evalExpr(right, vars, roleMgr)
	}

	// 处理 || （逻辑或）— 需要考虑括号嵌套
	if topOr := me.findTopLevelOp(expr, "||"); topOr >= 0 {
		left := expr[:topOr]
		right := expr[topOr+2:]
		return me.evalExpr(left, vars, roleMgr) || me.evalExpr(right, vars, roleMgr)
	}

	// 处理 g() 函数调用
	if strings.Contains(expr, "g(") {
		return me.evalGFunction(expr, vars, roleMgr)
	}

	// 处理 == 比较
	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		left := me.resolveValue(strings.TrimSpace(parts[0]), vars)
		right := me.resolveValue(strings.TrimSpace(parts[1]), vars)
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right)
	}

	// 处理 != 比较
	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		left := me.resolveValue(strings.TrimSpace(parts[0]), vars)
		right := me.resolveValue(strings.TrimSpace(parts[1]), vars)
		return fmt.Sprintf("%v", left) != fmt.Sprintf("%v", right)
	}

	// 处理 in 运算符：r.sub in ("alice","bob")
	if strings.Contains(expr, " in ") {
		return me.evalInExpr(expr, vars)
	}

	return false
}

// findTopLevelOp 查找顶层（不在括号内）的运算符位置
// 用于正确处理包含括号的表达式，如 g(r.sub, p.sub) && r.obj == p.obj
func (me *MatcherEngine) findTopLevelOp(expr string, op string) int {
	depth := 0
	for i := 0; i <= len(expr)-len(op); i++ {
		ch := expr[i]
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
		}
		if depth == 0 && expr[i:i+len(op)] == op {
			return i
		}
	}
	return -1
}

// evalInExpr 评估 in 运算符表达式
// 语法：value in ("item1","item2","item3")
// 判断 value 是否在给定的集合中
func (me *MatcherEngine) evalInExpr(expr string, vars map[string]interface{}) bool {
	inIdx := strings.Index(expr, " in ")
	if inIdx < 0 {
		return false
	}

	leftToken := strings.TrimSpace(expr[:inIdx])
	rightPart := strings.TrimSpace(expr[inIdx+4:])

	leftVal := fmt.Sprintf("%v", me.resolveValue(leftToken, vars))

	if !strings.HasPrefix(rightPart, "(") || !strings.HasSuffix(rightPart, ")") {
		return false
	}
	inner := rightPart[1 : len(rightPart)-1]
	items := strings.Split(inner, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, `"'`)
		if leftVal == item {
			return true
		}
	}
	return false
}

// evalGFunction 评估 g() 角色继承函数
// 支持 g(name1, name2) 和 g(name1, name2, domain) 两种形式
// g(r.sub, p.sub) 判断 r.sub 是否继承自 p.sub（即 r.sub 是否拥有 p.sub 角色）
// g(r.sub, p.sub, r.dom) 在指定域中判断角色继承
func (me *MatcherEngine) evalGFunction(expr string, vars map[string]interface{}, roleMgr *role.RoleManager) bool {
	matches := gFuncRegex.FindStringSubmatch(expr)
	if len(matches) < 3 {
		return false
	}

	name1Raw := strings.TrimSpace(matches[1])
	name2Raw := strings.TrimSpace(matches[2])

	name1 := fmt.Sprintf("%v", me.resolveValue(name1Raw, vars))
	name2 := fmt.Sprintf("%v", me.resolveValue(name2Raw, vars))

	if len(matches) >= 4 && matches[3] != "" {
		domain := fmt.Sprintf("%v", me.resolveValue(strings.TrimSpace(matches[3]), vars))
		return me.evaluateRoleFunctionWithDomain(name1, name2, domain, roleMgr)
	}

	return me.evaluateRoleFunction(name1, name2, roleMgr)
}

// evaluateRoleFunction 判断 name1 是否继承自 name2（无域）
func (me *MatcherEngine) evaluateRoleFunction(name1, name2 string, roleMgr *role.RoleManager) bool {
	if roleMgr == nil {
		return name1 == name2
	}
	return roleMgr.HasLink(name1, name2)
}

// evaluateRoleFunctionWithDomain 判断 name1 在指定域中是否继承自 name2
func (me *MatcherEngine) evaluateRoleFunctionWithDomain(name1, name2, domain string, roleMgr *role.RoleManager) bool {
	if roleMgr == nil {
		return name1 == name2
	}
	return roleMgr.HasLink(name1, name2, domain)
}

// buildVariableMap 构建变量映射表
// 将请求参数（r 段）和策略行（p 段）合并为一个统一的变量表
// 例如：{r.sub: "alice", r.obj: "data1", p.sub: "admin", p.obj: "data1"}
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

// resolveValue 解析变量值
// 支持三种解析方式：
//  1. 直接变量查找：vars["r.sub"] → "alice"
//  2. 嵌套属性访问：vars["r.obj"] 是结构体 → 访问 r.obj.Owner
//     对于 r.obj.Owner，先找 vars["r.obj"]，再访问其 Owner 字段
//  3. 字面量：不在 vars 中的值视为字面量，去掉引号后返回
func (me *MatcherEngine) resolveValue(token string, vars map[string]interface{}) interface{} {
	// 直接查找
	if val, ok := vars[token]; ok {
		return val
	}

	// 嵌套属性访问：尝试逐级查找
	// 例如 r.obj.Owner → 先找 r.obj，再访问 Owner
	if strings.Contains(token, ".") {
		parts := strings.Split(token, ".")
		// 从最长前缀开始尝试
		for i := len(parts) - 1; i >= 1; i-- {
			prefix := strings.Join(parts[:i], ".")
			if root, ok := vars[prefix]; ok {
				remaining := strings.Join(parts[i:], ".")
				accessor := safe.Safe(root)
				result := accessor.Field(remaining)
				if result.IsValid() {
					return result.Value()
				}
				// 尝试逐级访问
				current := root
				for j := i; j < len(parts); j++ {
					a := safe.Safe(current)
					r := a.Field(parts[j])
					if !r.IsValid() {
						break
					}
					current = r.Value()
					if j == len(parts)-1 {
						return current
					}
				}
			}
		}
	}

	// 字面量处理：去掉引号
	if (strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`)) ||
		(strings.HasPrefix(token, `'`) && strings.HasSuffix(token, `'`)) {
		return token[1 : len(token)-1]
	}

	return token
}
