/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
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
