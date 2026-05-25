/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-25 10:32:04
 * @FilePath: \go-casbin\policy\effect_test.go
 * @Description: 策略效果评估器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectEvaluator_SomeWhereAllow(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p.eft == allow))")
	result, err := ee.Evaluate([]string{"allow"})
	assert.NoError(t, err)
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_SomeWhereDeny(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p.eft == deny))")
	result, err := ee.Evaluate([]string{"deny"})
	assert.NoError(t, err)
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_NotSomeWhere(t *testing.T) {
	ee := NewEffectEvaluator("!some(where (p.eft == deny))")
	result, err := ee.Evaluate([]string{"allow"})
	assert.NoError(t, err)
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_Empty(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p.eft == allow))")
	result, err := ee.Evaluate([]string{})
	assert.NoError(t, err)
	assert.Equal(t, EffectDenyResult, result)
}

func TestEffectEvaluator_Default(t *testing.T) {
	ee := NewEffectEvaluator("custom")
	result, err := ee.Evaluate([]string{"allow"})
	assert.NoError(t, err)
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_Default_Deny(t *testing.T) {
	ee := NewEffectEvaluator("custom")
	result, err := ee.Evaluate([]string{"deny"})
	assert.NoError(t, err)
	assert.Equal(t, EffectDenyResult, result)
}

func TestEffectEvaluator_Default_NoMatch(t *testing.T) {
	ee := NewEffectEvaluator("custom")
	result, err := ee.Evaluate([]string{"other"})
	assert.Error(t, err)
	assert.Equal(t, EffectDenyResult, result)
}

func TestEffectEvaluator_GetExpression(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p.eft == allow))")
	assert.Equal(t, "some(where (p.eft == allow))", ee.GetExpression())
}

// evaluateSomeWhereP 使用 p_eft 格式表达式的测试
func TestEffectEvaluator_SomeWhereP_Allow(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p_eft == allow))")
	result, err := ee.evaluateSomeWhereP([]string{"allow"}, ee.effectExpr)
	assert.NoError(t, err)
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_SomeWhereP_Deny(t *testing.T) {
	ee := NewEffectEvaluator("some(where (p_eft == allow))")
	result, err := ee.evaluateSomeWhereP([]string{"deny"}, ee.effectExpr)
	assert.NoError(t, err)
	assert.Equal(t, EffectDenyResult, result)
}

func TestEffectEvaluator_NotSomeWhere_Deny(t *testing.T) {
	ee := NewEffectEvaluator("!some(where (p.eft == deny))")
	result, err := ee.Evaluate([]string{"deny"})
	assert.NoError(t, err)
	assert.Equal(t, EffectDenyResult, result)
}

func TestEffectEvaluator_NotSomeWhere_AllowExpr(t *testing.T) {
	// 表达式不含 "deny" 时，targetEffect 仍为 EffectDeny（默认值）
	ee := NewEffectEvaluator("!some(where (p.eft == allow))")
	result, err := ee.evaluateNotSomeWhere([]string{"allow"}, ee.effectExpr)
	assert.NoError(t, err)
	// targetEffect=deny，effects 中没有 deny，所以返回 Allow
	assert.Equal(t, EffectAllowResult, result)
}

func TestEffectEvaluator_Evaluate_InvalidExpr(t *testing.T) {
	ee := NewEffectEvaluator("")
	result, err := ee.Evaluate([]string{"allow"})
	assert.NoError(t, err)
	// 空表达式走默认评估
	assert.Equal(t, EffectAllowResult, result)
}
