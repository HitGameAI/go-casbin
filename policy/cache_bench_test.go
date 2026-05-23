/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\policy\cache_bench_test.go
 * @Description: 策略缓存性能基准测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"
)

// BenchmarkPolicyCache_Set 缓存写入
func BenchmarkPolicyCache_Set(b *testing.B) {
	pc := NewPolicyCache()
	policies := [][]string{{"alice", "data1", "read"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.Set("p", policies)
	}
}

// BenchmarkPolicyCache_Get 缓存读取命中
func BenchmarkPolicyCache_Get(b *testing.B) {
	pc := NewPolicyCache()
	policies := make([][]string, 100)
	for i := range policies {
		policies[i] = []string{"user", "resource", "action"}
	}
	pc.Set("p", policies)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.Get("p")
	}
}

// BenchmarkPolicyCache_Get_Miss 缓存读取未命中
func BenchmarkPolicyCache_Get_Miss(b *testing.B) {
	pc := NewPolicyCache()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.Get("nonexistent")
	}
}

// BenchmarkPolicyCache_Lookup 缓存查找
func BenchmarkPolicyCache_Lookup(b *testing.B) {
	pc := NewPolicyCache()
	policies := make([][]string, 100)
	for i := range policies {
		policies[i] = []string{"user" + string(rune('0'+i%10)), "resource", "action"}
	}
	policies[50] = []string{"target", "resource", "action"}
	pc.Set("p", policies)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.Lookup("p", []string{"target", "resource", "action"})
	}
}

// BenchmarkPolicyCache_Invalidate 缓存失效
func BenchmarkPolicyCache_Invalidate(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc := NewPolicyCache()
		pc.Set("p", [][]string{{"alice", "data1", "read"}})
		pc.Invalidate("p")
	}
}
