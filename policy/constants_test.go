/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\constants_test.go
 * @Description: 策略相关常量测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPTypeConstants_FromModel(t *testing.T) {
	assert.Equal(t, "p", PTypePolicy)
	assert.Equal(t, "p2", PTypePolicy2)
	assert.Equal(t, "g", PTypeGrouping)
	assert.Equal(t, "g2", PTypeGrouping2)
}

func TestPTypeConstants_Aliases(t *testing.T) {
	assert.Equal(t, PTypePolicy, PTypePolicy)
	assert.Equal(t, PTypePolicy2, PTypePolicy2)
	assert.Equal(t, PTypeGrouping, PTypeGrouping)
	assert.Equal(t, PTypeGrouping2, PTypeGrouping2)
}

func TestPolicyFields(t *testing.T) {
	assert.Len(t, PolicyFields, MaxPolicyFields)
	assert.Equal(t, "v0", PolicyFields[0])
	assert.Equal(t, "v5", PolicyFields[5])
}

func TestAllFields(t *testing.T) {
	assert.Len(t, AllFields, MaxPolicyFields+1)
	assert.Equal(t, "p_type", AllFields[0])
}

func TestGetFieldByIndex(t *testing.T) {
	assert.Equal(t, "v0", GetFieldByIndex(0))
	assert.Equal(t, "v5", GetFieldByIndex(5))
	assert.Equal(t, "", GetFieldByIndex(-1))
	assert.Equal(t, "", GetFieldByIndex(6))
}

func TestGetFieldsFromIndex(t *testing.T) {
	result := GetFieldsFromIndex(0, 3)
	assert.Equal(t, []string{"v0", "v1", "v2"}, result)

	result = GetFieldsFromIndex(4, 10)
	assert.Equal(t, []string{"v4", "v5"}, result)

	assert.Nil(t, GetFieldsFromIndex(-1, 3))
	assert.Nil(t, GetFieldsFromIndex(6, 3))
}

func TestIndexConstants(t *testing.T) {
	assert.Equal(t, 0, IdxSub)
	assert.Equal(t, 1, IdxDom)
	assert.Equal(t, 2, IdxObj)
	assert.Equal(t, 3, IdxAct)
	assert.Equal(t, 4, IdxEft)
	assert.Equal(t, 5, IdxExtra)
}
