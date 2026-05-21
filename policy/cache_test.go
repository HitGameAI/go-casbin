/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\cache_test.go
 * @Description: 策略缓存测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyCache_SetGet(t *testing.T) {
	cache := NewPolicyCache()
	policies := [][]string{{"alice", "data1", "read"}}

	cache.Set("p", policies)
	result, ok := cache.Get("p")
	assert.True(t, ok)
	assert.Equal(t, policies, result)
}

func TestPolicyCache_Get_NotFound(t *testing.T) {
	cache := NewPolicyCache()
	_, ok := cache.Get("p")
	assert.False(t, ok)
}

func TestPolicyCache_Invalidate(t *testing.T) {
	cache := NewPolicyCache()
	cache.Set("p", [][]string{{"alice", "data1", "read"}})
	cache.Invalidate("p")
	_, ok := cache.Get("p")
	assert.False(t, ok)
}

func TestPolicyCache_InvalidateAll(t *testing.T) {
	cache := NewPolicyCache()
	cache.Set("p", [][]string{{"alice", "data1", "read"}})
	cache.Set("g", [][]string{{"alice", "admin"}})
	cache.InvalidateAll()
	_, ok1 := cache.Get("p")
	_, ok2 := cache.Get("g")
	assert.False(t, ok1)
	assert.False(t, ok2)
}

func TestPolicyCache_Lookup(t *testing.T) {
	cache := NewPolicyCache()
	cache.Set("p", [][]string{{"alice", "data1", "read"}})

	assert.True(t, cache.Lookup("p", []string{"alice", "data1", "read"}))
	assert.False(t, cache.Lookup("p", []string{"bob", "data2", "write"}))
	assert.False(t, cache.Lookup("g", []string{"alice", "admin"}))
}

func TestPolicyCache_Size(t *testing.T) {
	cache := NewPolicyCache()
	cache.Set("p", [][]string{{"alice", "data1", "read"}})
	cache.Set("g", [][]string{{"alice", "admin"}})
	assert.Equal(t, 2, cache.Size())
}
