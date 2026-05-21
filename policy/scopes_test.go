/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\scopes_test.go
 * @Description: 策略作用域与工具函数测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ==================== 策略比较测试 ====================

func TestArrayEquals(t *testing.T) {
	assert.True(t, ArrayEquals([]string{"a", "b"}, []string{"a", "b"}))
	assert.False(t, ArrayEquals([]string{"a", "b"}, []string{"a", "c"}))
	assert.False(t, ArrayEquals([]string{"a"}, []string{"a", "b"}))
}

func TestArray2DEquals(t *testing.T) {
	a := [][]string{{"a", "b"}, {"c", "d"}}
	b := [][]string{{"a", "b"}, {"c", "d"}}
	assert.True(t, Array2DEquals(a, b))

	c := [][]string{{"a", "b"}}
	assert.False(t, Array2DEquals(a, c))
}

func TestSortedArray2DEquals(t *testing.T) {
	a := [][]string{{"c", "d"}, {"a", "b"}}
	b := [][]string{{"a", "b"}, {"c", "d"}}
	assert.True(t, SortedArray2DEquals(a, b))

	c := [][]string{{"a", "b"}}
	assert.False(t, SortedArray2DEquals(a, c))
}

// ==================== 排序测试 ====================

func TestSortArray2D(t *testing.T) {
	arr := [][]string{{"c", "d"}, {"a", "b"}, {"a", "a"}}
	SortArray2D(arr)
	assert.Equal(t, [][]string{{"a", "a"}, {"a", "b"}, {"c", "d"}}, arr)
}

func TestSortArray2D_Empty(t *testing.T) {
	arr := [][]string{}
	SortArray2D(arr)
	assert.Empty(t, arr)
}

// ==================== 去重测试 ====================

func TestArrayRemoveDuplicates(t *testing.T) {
	s := &[]string{"a", "b", "a", "c", "b"}
	ArrayRemoveDuplicates(s)
	assert.Equal(t, []string{"a", "b", "c"}, *s)
}

func TestRemoveDuplicateElements(t *testing.T) {
	result := RemoveDuplicateElements([]string{"a", "b", "a", "c", "b"})
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

// ==================== 集合运算测试 ====================

func TestSetEquals(t *testing.T) {
	assert.True(t, SetEquals([]string{"a", "b"}, []string{"b", "a"}))
	assert.False(t, SetEquals([]string{"a", "b"}, []string{"a", "c"}))
	assert.False(t, SetEquals([]string{"a"}, []string{"a", "b"}))
}

func TestSet2DEquals(t *testing.T) {
	a := [][]string{{"b", "a"}, {"d", "c"}}
	b := [][]string{{"a", "b"}, {"c", "d"}}
	assert.True(t, Set2DEquals(a, b))
}

func TestSetSubtract(t *testing.T) {
	a := []string{"a", "b", "c", "d"}
	b := []string{"b", "d"}
	result := SetSubtract(a, b)
	assert.Equal(t, []string{"a", "c"}, result)
}

// ==================== 拼接工具测试 ====================

func TestArrayToString(t *testing.T) {
	assert.Equal(t, "a, b, c", ArrayToString([]string{"a", "b", "c"}))
}

func TestParamsToString(t *testing.T) {
	assert.Equal(t, "a, b, c", ParamsToString("a", "b", "c"))
}

func TestJoinSlice(t *testing.T) {
	result := JoinSlice("a", "b", "c")
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestJoinSliceAny(t *testing.T) {
	result := JoinSliceAny("a", "b", "c")
	assert.Equal(t, []interface{}{"a", "b", "c"}, result)
}

// ==================== PolicyScope 测试 ====================

func TestNewPolicyScope(t *testing.T) {
	scope := NewPolicyScope("tenant1", "ns1", "p")
	assert.Equal(t, "tenant1", scope.Domain)
	assert.Equal(t, "ns1", scope.Namespace)
	assert.Equal(t, "p", scope.PType)
}

func TestPolicyScope_String(t *testing.T) {
	scope := NewPolicyScope("tenant1", "ns1", "p")
	assert.Equal(t, "tenant1/ns1/p", scope.String())

	emptyScope := NewPolicyScope("", "", "")
	assert.Equal(t, "", emptyScope.String())

	partialScope := NewPolicyScope("tenant1", "", "p")
	assert.Equal(t, "tenant1/p", partialScope.String())
}

func TestPolicyScope_CacheKey(t *testing.T) {
	scope := NewPolicyScope("tenant1", "ns1", "p")
	assert.Equal(t, "scope:tenant1/ns1/p", scope.CacheKey())
}

func TestPolicyScope_IsGlobal(t *testing.T) {
	globalScope := NewPolicyScope("", "", "p")
	assert.True(t, globalScope.IsGlobal())

	domainScope := NewPolicyScope("tenant1", "", "p")
	assert.False(t, domainScope.IsGlobal())
}

func TestPolicyScope_Matches(t *testing.T) {
	// 全局作用域匹配所有行
	globalScope := NewPolicyScope("", "", "")
	assert.True(t, globalScope.Matches("p, alice, data1, read"))
	assert.True(t, globalScope.Matches("g, alice, admin"))

	// PType 不为空但 Domain/Namespace 为空时，IsGlobal 仍为 true
	// 因为 IsGlobal 只检查 Domain 和 Namespace
	typeOnlyScope := NewPolicyScope("", "", "p")
	assert.True(t, typeOnlyScope.IsGlobal()) // Domain="" && Namespace=""
	assert.True(t, typeOnlyScope.Matches("p, alice, data1, read"))
	assert.True(t, typeOnlyScope.Matches("g, alice, admin"))

	// 有域限制时，按 PType 过滤
	domainScope := NewPolicyScope("tenant1", "", "p")
	assert.False(t, domainScope.IsGlobal())
	assert.True(t, domainScope.Matches("p, tenant1, data1, read"))
	assert.False(t, domainScope.Matches("g, alice, admin"))
}
