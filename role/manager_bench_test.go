/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\role\manager_bench_test.go
 * @Description: 角色管理器性能基准测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package role

import (
	"testing"

	"github.com/kamalyes/go-logger"
)

// BenchmarkRoleManager_HasLink_CacheHit 缓存命中场景
func BenchmarkRoleManager_HasLink_CacheHit(b *testing.B) {
	rm := NewRoleManager(logger.NoLogger)
	rm.AddLink("alice", "admin")
	rm.AddLink("admin", "superadmin")

	// 预热缓存
	rm.HasLink("alice", "superadmin")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.HasLink("alice", "superadmin")
	}
}

// BenchmarkRoleManager_HasLink_CacheMiss 缓存未命中场景（每次新建）
func BenchmarkRoleManager_HasLink_CacheMiss(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm := NewRoleManager(logger.NoLogger)
		rm.AddLink("alice", "admin")
		rm.HasLink("alice", "admin")
	}
}

// BenchmarkRoleManager_HasLink_DeepHierarchy 深层继承链场景
func BenchmarkRoleManager_HasLink_DeepHierarchy(b *testing.B) {
	rm := NewRoleManager(logger.NoLogger)
	rm.AddLink("user", "r1")
	rm.AddLink("r1", "r2")
	rm.AddLink("r2", "r3")
	rm.AddLink("r3", "r4")
	rm.AddLink("r4", "r5")

	// 预热缓存
	rm.HasLink("user", "r5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.HasLink("user", "r5")
	}
}

// BenchmarkRoleManager_HasLink_WithDomain 域隔离场景
func BenchmarkRoleManager_HasLink_WithDomain(b *testing.B) {
	rm := NewRoleManager(logger.NoLogger)
	rm.AddLink("alice", "admin", "tenant1")
	rm.AddLink("admin", "superadmin", "tenant1")

	rm.HasLink("alice", "superadmin", "tenant1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.HasLink("alice", "superadmin", "tenant1")
	}
}

// BenchmarkRoleManager_GetImplicitRoles 递归获取隐式角色
func BenchmarkRoleManager_GetImplicitRoles(b *testing.B) {
	rm := NewRoleManager(logger.NoLogger)
	rm.AddLink("alice", "admin")
	rm.AddLink("admin", "editor")
	rm.AddLink("editor", "viewer")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.GetImplicitRoles("alice")
	}
}

// BenchmarkRoleManager_AddLink 添加角色链接（含缓存失效）
func BenchmarkRoleManager_AddLink(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm := NewRoleManager(logger.NoLogger)
		rm.AddLink("user", "role1")
	}
}

// BenchmarkRoleManager_ManyRoles 大量角色场景
func BenchmarkRoleManager_ManyRoles(b *testing.B) {
	rm := NewRoleManager(logger.NoLogger)
	for i := 0; i < 100; i++ {
		rm.AddLink("user", "role")
	}
	rm.HasLink("user", "role")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.HasLink("user", "role")
	}
}
