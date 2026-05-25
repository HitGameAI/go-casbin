/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\filter_test.go
 * @Description: 策略过滤器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ==================== Filter 结构体测试 ====================

func TestNewFilter(t *testing.T) {
	f := NewFilter()
	assert.NotNil(t, f)
	assert.True(t, f.IsEmpty())
}

func TestFilter_ChainMethods(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice").WithV1("data1").WithV2("read").WithV3("allow").WithV4("extra").WithV5("ext2")
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
	assert.Equal(t, "allow", f.V3)
	assert.Equal(t, "extra", f.V4)
	assert.Equal(t, "ext2", f.V5)
	assert.False(t, f.IsEmpty())
}

func TestFilter_Values(t *testing.T) {
	f := NewFilter().WithV0("alice").WithV1("data1")
	values := f.Values()
	assert.Len(t, values, 6)
	assert.Equal(t, "alice", values[0])
	assert.Equal(t, "data1", values[1])
}

func TestFilter_AllValues(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")
	all := f.AllValues()
	assert.Len(t, all, 7)
	assert.Equal(t, "p", all[0])
	assert.Equal(t, "alice", all[1])
}

func TestFilter_NonEmptyFields(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")
	fields := f.NonEmptyFields()
	assert.Len(t, fields, 2)
	assert.Equal(t, "p", fields[FieldPType])
	assert.Equal(t, "alice", fields[FieldV0])
}

func TestFilter_IsEmpty(t *testing.T) {
	assert.True(t, NewFilter().IsEmpty())
	assert.False(t, NewFilter().WithPType("p").IsEmpty())
	assert.False(t, NewFilter().WithV0("alice").IsEmpty())
}

func TestFilter_FromSlice(t *testing.T) {
	f := NewFilter().FromSlice([]string{"p", "alice", "data1", "read"})
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
}

func TestFilterFromSlice(t *testing.T) {
	f := FilterFromSlice([]string{"p", "alice", "data1", "read", "tenant1", "extra", "field"})
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
	assert.Equal(t, "tenant1", f.V3)
	assert.Equal(t, "extra", f.V4)
	assert.Equal(t, "field", f.V5)
}

func TestFilter_Match(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")

	assert.True(t, f.Match("p, alice, data1, read"))
	assert.False(t, f.Match("p, bob, data1, read"))
	assert.False(t, f.Match("g, alice, admin"))
}

func TestFilter_Match_Empty(t *testing.T) {
	f := NewFilter()
	assert.True(t, f.Match("p, alice, data1, read"))
}

func TestMatchByIndex(t *testing.T) {
	assert.True(t, MatchByIndex("p, alice, data1, read", 1, "alice"))
	assert.True(t, MatchByIndex("p, alice, data1, read", 1, "alice", "data1"))
	assert.False(t, MatchByIndex("p, alice, data1, read", 1, "bob"))
}

func TestFilterPolicies(t *testing.T) {
	policies := []string{
		"p, alice, data1, read",
		"p, bob, data2, write",
		"g, alice, admin",
	}

	// 按过滤器过滤
	filter := NewFilter().WithPType("p")
	result := FilterPolicies(policies, filter)
	assert.Len(t, result, 2)

	// nil 过滤器
	result = FilterPolicies(policies, nil)
	assert.Len(t, result, 3)

	// 空过滤器
	result = FilterPolicies(policies, NewFilter())
	assert.Len(t, result, 3)
}

func TestFilterPoliciesByIndex(t *testing.T) {
	policies := []string{
		"p, alice, data1, read",
		"p, bob, data2, write",
	}

	result := FilterPoliciesByIndex(policies, 1, "alice")
	assert.Len(t, result, 1)

	// 空 fieldValues
	result = FilterPoliciesByIndex(policies, 1)
	assert.Len(t, result, 2)
}

func TestExtractPType(t *testing.T) {
	assert.Equal(t, "p", ExtractPType("p, alice, data1, read"))
	assert.Equal(t, "g", ExtractPType("g, alice, admin"))
	assert.Equal(t, "p", ExtractPType("p"))
	assert.Equal(t, "", ExtractPType(""))
}
