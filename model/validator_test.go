/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\validator_test.go
 * @Description: 模型验证器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateModel_MissingSection(t *testing.T) {
	assertions := map[string]*Assertion{
		"r": NewAssertion("r", "sub, obj, act"),
	}
	err := ValidateModel(assertions)
	assert.Error(t, err)
}

func TestValidateModel_EmptyTokens(t *testing.T) {
	assertions := map[string]*Assertion{
		"r": NewAssertion("r", ""),
		"p": NewAssertion("p", "sub, obj, act"),
		"e": NewAssertion("e", "some(where (p.eft == allow))"),
		"m": NewAssertion("m", "r.sub == p.sub"),
	}
	err := ValidateModel(assertions)
	assert.Error(t, err)
}

func TestValidateModel_EmptyEffect(t *testing.T) {
	assertions := map[string]*Assertion{
		"r": NewAssertion("r", "sub, obj, act"),
		"p": NewAssertion("p", "sub, obj, act"),
		"e": NewAssertion("e", ""),
		"m": NewAssertion("m", "r.sub == p.sub"),
	}
	err := ValidateModel(assertions)
	assert.Error(t, err)
}

func TestValidateModel_PolicyDefinitionNoTokens(t *testing.T) {
	// r 有 tokens（通过 validateRequestDefinition），但 p 无 tokens（触发 validatePolicyDefinition 错误分支）
	assertions := map[string]*Assertion{
		"r": NewAssertion("r", "sub, obj, act"),
		"p": NewAssertion("p", ""),
		"e": NewAssertion("e", "some(where (p.eft == allow))"),
		"m": NewAssertion("m", "r.sub == p.sub"),
	}
	err := ValidateModel(assertions)
	assert.Error(t, err)
}

func TestValidateModel_Valid(t *testing.T) {
	assertions := map[string]*Assertion{
		"r": NewAssertion("r", "sub, obj, act"),
		"p": NewAssertion("p", "sub, obj, act"),
		"e": NewAssertion("e", "some(where (p.eft == allow))"),
		"m": NewAssertion("m", "r.sub == p.sub"),
	}
	err := ValidateModel(assertions)
	assert.NoError(t, err)
}
