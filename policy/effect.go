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

// 效果评估模式枚举
// 在 NewEffectEvaluator 时预计算，避免每次 Evaluate 重复 strings.ToLower + Contains 扫描
const (
	evalModeNotSomeWhere = iota // !some(where (p.eft == deny))
	evalModeSomeWhere           // some(where (p.eft == allow/deny))
	evalModeSomeWhereP          // some(where (p_eft == allow))（与 SomeWhere 相同处理，向后兼容）
	evalModeDefault             // 默认评估
)

// EffectEvaluator 策略效果评估器
// 根据模型中定义的策略效果表达式（e 段），评估多条策略的组合效果
// 支持的表达式：
//   - some(where (p.eft == allow))：任一策略允许则允许（白名单）
//   - !some(where (p.eft == deny))：没有策略拒绝则允许（黑名单）
//   - some(where (p.eft == allow)) && !some(where (p.eft == deny))：有允许且无拒绝才允许
//
// 性能优化：evalMode/targetEffect 在构造时预计算，Evaluate 热路径仅 switch + 遍历 effects
type EffectEvaluator struct {
	effectExpr   string // 策略效果表达式（原始，用于 GetExpression）
	evalMode     int    // 预计算的评估模式，避免每次 Evaluate 重复 strings.ToLower + Contains
	targetEffect string // 预计算的目标效果（allow/deny），避免每次遍历前重复 Contains
}

// NewEffectEvaluator 创建策略效果评估器
// effectExpr 为模型 e 段定义的效果表达式
// 构造时预计算 evalMode 和 targetEffect，消除 Evaluate 热路径上的字符串扫描
func NewEffectEvaluator(effectExpr string) *EffectEvaluator {
	expr := strings.TrimSpace(effectExpr)
	lower := strings.ToLower(expr)

	mode := evalModeDefault
	target := EffectAllow

	switch {
	case strings.Contains(lower, "!some(where"):
		mode = evalModeNotSomeWhere
		target = EffectDeny // evaluateNotSomeWhere: targetEffect 总是 Deny
	case strings.Contains(lower, "some(where (p_eft"):
		mode = evalModeSomeWhereP
		if strings.Contains(lower, EffectDeny) {
			target = EffectDeny
		}
	case strings.Contains(lower, "some(where"):
		mode = evalModeSomeWhere
		if strings.Contains(lower, EffectDeny) {
			target = EffectDeny
		}
	}

	return &EffectEvaluator{
		effectExpr:   expr,
		evalMode:     mode,
		targetEffect: target,
	}
}

// Evaluate 评估策略效果
// 根据效果表达式和各条策略的效果值，决定最终的允许/拒绝结果
// 无匹配策略时默认拒绝
//
// 性能：使用预计算的 evalMode/targetEffect，避免每次调用 strings.ToLower + 多次 Contains
func (ee *EffectEvaluator) Evaluate(effects []string) (EffectResult, error) {
	if len(effects) == 0 {
		return EffectDenyResult, nil
	}

	switch ee.evalMode {
	case evalModeNotSomeWhere:
		// !some(where (p.eft == deny))：没有匹配 deny 则允许
		for _, eft := range effects {
			if eft == ee.targetEffect {
				return EffectDenyResult, nil
			}
		}
		return EffectAllowResult, nil
	case evalModeSomeWhere, evalModeSomeWhereP:
		// some(where (p.eft == allow/deny))：匹配目标效果即允许
		for _, eft := range effects {
			if eft == ee.targetEffect {
				return EffectAllowResult, nil
			}
		}
		return EffectDenyResult, nil
	default:
		return ee.evaluateDefault(effects)
	}
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
