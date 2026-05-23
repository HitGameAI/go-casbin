/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 09:51:16
 * @FilePath: \go-casbin\policy\cache.go
 * @Description: 策略缓存（基于 syncx.Map）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"strings"

	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// cacheEntry 缓存条目，存储某个策略类型的所有策略规则
type cacheEntry struct {
	Policies [][]string      // 策略规则列表，每条规则为字符串切片
	Index    map[string]bool // 策略快速查找索引，key 为 "v0,v1,v2,..."
}

// PolicyCache 策略缓存
// 基于 go-toolbox/syncx.Map 实现的并发安全缓存
// 用于加速策略查询，避免每次都遍历内存模型
type PolicyCache struct {
	cache syncx.Map[string, *cacheEntry] // 并发安全映射，key 为策略类型（如 "p"、"g"）
}

// NewPolicyCache 创建策略缓存实例
func NewPolicyCache() *PolicyCache {
	return &PolicyCache{}
}

// Get 根据策略类型获取缓存中的策略规则
// 返回策略列表和是否找到的标志
func (pc *PolicyCache) Get(ptype string) ([][]string, bool) {
	entry, ok := pc.cache.Load(ptype)
	if !ok {
		return nil, false
	}
	return entry.Policies, true
}

// Set 设置指定策略类型的缓存
func (pc *PolicyCache) Set(ptype string, policies [][]string) {
	pc.cache.Store(ptype, &cacheEntry{
		Policies: policies,
		Index:    buildIndex(policies),
	})
}

// buildIndex 为策略列表构建 hash 索引，O(1) 查找替代 O(n) 线性扫描
func buildIndex(policies [][]string) map[string]bool {
	idx := make(map[string]bool, len(policies))
	for _, p := range policies {
		idx[strings.Join(p, ",")] = true
	}
	return idx
}

// Invalidate 使指定策略类型的缓存失效
// 通常在策略增删改后调用
func (pc *PolicyCache) Invalidate(ptype string) {
	pc.cache.Delete(ptype)
}

// InvalidateAll 使所有策略类型的缓存失效
// 通常在策略全量加载后调用
func (pc *PolicyCache) InvalidateAll() {
	pc.cache.Range(func(key string, value *cacheEntry) bool {
		pc.cache.Delete(key)
		return true
	})
}

// Lookup 在缓存中查找指定策略是否存在
// 使用 hash 索引实现 O(1) 查找，替代原来的 O(n) 线性扫描
func (pc *PolicyCache) Lookup(ptype string, policy []string) bool {
	entry, ok := pc.cache.Load(ptype)
	if !ok {
		return false
	}
	return entry.Index[fastJoin(policy)]
}

// fastJoin 快速拼接字符串切片，避免 strings.Join 的额外分配
func fastJoin(parts []string) string {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p)
	}
	return b.String()
}

// Size 返回缓存中的策略类型数量
func (pc *PolicyCache) Size() int {
	count := 0
	pc.cache.Range(func(key string, value *cacheEntry) bool {
		count++
		return true
	})
	return count
}
