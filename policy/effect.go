/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\effect.go
 * @Description: 策略效果评估器
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"strings"

	"github.com/kamalyes/go-casbin/errors"
)

// 策略效果常量
const (
	EffectAllow = "allow" // 允许
	EffectDeny  = "deny"  // 拒绝
)

// EffectResult 策略效果评估结果
// true 表示允许，false 表示拒绝
type EffectResult bool

const (
	EffectAllowResult EffectResult = true  // 允许结果
	EffectDenyResult  EffectResult = false // 拒绝结果
)

// EffectEvaluator 策略效果评估器
// 根据模型中定义的策略效果表达式（e 段），评估多条策略的组合效果
// 支持的表达式：
//   - some(where (p.eft == allow))：任一策略允许则允许（白名单）
//   - !some(where (p.eft == deny))：没有策略拒绝则允许（黑名单）
//   - some(where (p.eft == allow)) && !some(where (p.eft == deny))：有允许且无拒绝才允许
type EffectEvaluator struct {
	effectExpr string // 策略效果表达式
}

// NewEffectEvaluator 创建策略效果评估器
// effectExpr 为模型 e 段定义的效果表达式
func NewEffectEvaluator(effectExpr string) *EffectEvaluator {
	return &EffectEvaluator{effectExpr: strings.TrimSpace(effectExpr)}
}

// Evaluate 评估策略效果
// 根据效果表达式和各条策略的效果值，决定最终的允许/拒绝结果
// 无匹配策略时默认拒绝
func (ee *EffectEvaluator) Evaluate(effects []string) (EffectResult, error) {
	if len(effects) == 0 {
		return EffectDenyResult, nil
	}

	expr := strings.ToLower(ee.effectExpr)

	switch {
	case strings.Contains(expr, "!some(where"):
		return ee.evaluateNotSomeWhere(effects, expr)
	case strings.Contains(expr, "some(where"):
		return ee.evaluateSomeWhere(effects, expr)
	case strings.Contains(expr, "some(where (p_eft"):
		return ee.evaluateSomeWhereP(effects, expr)
	default:
		return ee.evaluateDefault(effects)
	}
}

// evaluateSomeWhere 评估 "some(where (p.eft == allow/deny))" 表达式
// 只要有一条策略匹配目标效果就允许
func (ee *EffectEvaluator) evaluateSomeWhere(effects []string, expr string) (EffectResult, error) {
	targetEffect := EffectAllow
	if strings.Contains(expr, EffectDeny) {
		targetEffect = EffectDeny
	}

	for _, eft := range effects {
		if eft == targetEffect {
			return EffectAllowResult, nil
		}
	}
	return EffectDenyResult, nil
}

// evaluateNotSomeWhere 评估 "!some(where (p.eft == deny))" 表达式
// 没有任何策略匹配目标效果时才允许（即没有拒绝则允许）
func (ee *EffectEvaluator) evaluateNotSomeWhere(effects []string, expr string) (EffectResult, error) {
	targetEffect := EffectDeny
	if strings.Contains(expr, EffectDeny) {
		targetEffect = EffectDeny
	}

	for _, eft := range effects {
		if eft == targetEffect {
			return EffectDenyResult, nil
		}
	}
	return EffectAllowResult, nil
}

// evaluateSomeWhereP 评估 "some(where (p_eft == allow))" 表达式
// 与 evaluateSomeWhere 逻辑相同，处理 p_eft 格式的表达式
func (ee *EffectEvaluator) evaluateSomeWhereP(effects []string, expr string) (EffectResult, error) {
	return ee.evaluateSomeWhere(effects, expr)
}

// evaluateDefault 默认效果评估
// 优先检查是否有拒绝策略，有则拒绝；否则检查是否有允许策略
func (ee *EffectEvaluator) evaluateDefault(effects []string) (EffectResult, error) {
	for _, eft := range effects {
		if eft == EffectDeny {
			return EffectDenyResult, nil
		}
	}

	if len(effects) > 0 && effects[0] == EffectAllow {
		return EffectAllowResult, nil
	}

	return EffectDenyResult, errors.NewPolicyEffectDeniedError("no matching effect rule")
}

// GetExpression 获取当前效果表达式
func (ee *EffectEvaluator) GetExpression() string {
	return ee.effectExpr
}
