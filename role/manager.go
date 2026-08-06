/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 22:17:23
 * @FilePath: \go-casbin\role\manager.go
 * @Description: 角色管理器（含域支持、隐式查询、缓存）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

import (
	"strings"
	"sync"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
)

// RoleManager 角色管理器
// 在 RoleHierarchy 之上封装了缓存层和域支持，提供完整的 RBAC 角色管理能力
//
// 核心特性：
//   - 域隔离：通过 domain 参数实现多租户角色隔离（键格式 "domain:name"）
//   - 缓存加速：基于 syncx.Map 缓存 HasLink 查询结果，避免重复 DFS 遍历
//   - 隐式查询：GetImplicitRoles/GetImplicitUsers 递归获取所有间接继承关系
//   - 深度限制：maxDepth 防止递归查询过深导致性能问题
//
// 使用方式：
//
//	rm := NewRoleManager(log)
//	rm.AddLink("alice", "admin")                    // alice 继承 admin
//	rm.AddLink("alice", "editor", "tenant1")        // alice 在 tenant1 继承 editor
//	ok := rm.HasLink("alice", "viewer")             // 检查 alice 是否继承 viewer
//	roles := rm.GetImplicitRoles("alice")           // 获取 alice 的所有间接角色
type RoleManager struct {
	hierarchy *RoleHierarchy // 角色层级管理器（继承关系图）
	cache     sync.Map       // 缓存层（key="name1->name2" 或 "domain:name1->name2"，value=bool）
	nameIndex sync.Map       // name→cacheKeys 索引（value=map[string]struct{}），用于精准失效
	logger    logger.ILogger // 日志记录器
	maxDepth  int            // 递归查询最大深度（默认 10，防止无限递归）
}

// NewRoleManager 创建角色管理器
// log: 日志记录器，用于记录角色操作
func NewRoleManager(log logger.ILogger) *RoleManager {
	return &RoleManager{
		hierarchy: NewRoleHierarchy(log),
		logger:    log,
		maxDepth:  10,
	}
}

// AddLink 添加角色继承链接（支持域隔离）
// name1 继承 name2，可选指定 domain 实现多租户隔离
// 添加成功后自动失效相关缓存
// domain: 可选，指定租户域（如 "tenant1"）
func (rm *RoleManager) AddLink(name1, name2 string, domain ...string) error {
	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	if err := rm.hierarchy.AddLink(n1, n2); err != nil {
		return errors.WrapError("AddLink", err)
	}

	rm.invalidateCache(name1, domain...)
	rm.invalidateCache(name2, domain...)
	rm.logger.InfoKV("Role link added", "name1", name1, "name2", name2)
	return nil
}

// DeleteLink 删除角色继承链接（支持域隔离）
// 删除后自动失效相关缓存
func (rm *RoleManager) DeleteLink(name1, name2 string, domain ...string) {
	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	rm.hierarchy.DeleteLink(n1, n2)
	rm.invalidateCache(name1, domain...)
	rm.invalidateCache(name2, domain...)
	rm.logger.InfoKV("Role link deleted", "name1", name1, "name2", name2)
}

// HasLink 检查角色继承关系（含间接继承，支持域隔离和缓存）
// 优先从缓存读取结果，缓存未命中时委托给 RoleHierarchy 进行 DFS 查询
// 查询结果会写入缓存，后续相同查询直接命中缓存
//
// 性能优化：自链接（name1==name2）直接返回 true，跳过 buildCacheKey 的字符串拼接
// RBAC 场景中 g(r.sub, p.sub) 经常出现 r.sub==p.sub，避免热路径上的无谓分配
func (rm *RoleManager) HasLink(name1, name2 string, domain ...string) bool {
	if name1 == name2 {
		return true
	}

	cacheKey := rm.buildCacheKey(name1, name2, domain...)
	if result, ok := rm.cache.Load(cacheKey); ok {
		return result.(bool)
	}

	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	result := rm.hierarchy.HasLink(n1, n2)
	rm.cache.Store(cacheKey, result)
	// 维护 nameIndex：将 cacheKey 关联到 name1 和 name2，用于精准失效
	rm.addNameIndex(name1, cacheKey, domain...)
	rm.addNameIndex(name2, cacheKey, domain...)
	return result
}

// GetRoles 获取角色直接继承的角色列表（支持域隔离）
// 返回结果已去除域前缀，只保留角色名称
func (rm *RoleManager) GetRoles(name string, domain ...string) []string {
	n := rm.buildKey(name, domain)
	roles := rm.hierarchy.GetRoles(n)

	result := make([]string, 0, len(roles))
	for _, r := range roles {
		result = append(result, rm.stripDomain(r, domain...))
	}
	return result
}

// GetUsers 获取继承指定角色的所有用户（支持域隔离）
// 反向查询：找出所有直接继承 name 角色的角色
func (rm *RoleManager) GetUsers(name string, domain ...string) []string {
	n := rm.buildKey(name, domain)
	users := rm.hierarchy.GetUsers(n)

	result := make([]string, 0, len(users))
	for _, u := range users {
		result = append(result, rm.stripDomain(u, domain...))
	}
	return result
}

// GetImplicitRoles 递归获取所有间接继承的角色列表（支持域隔离）
// 例如：alice → admin → editor → viewer，返回 ["admin", "editor", "viewer"]
// 受 maxDepth 限制，防止无限递归
func (rm *RoleManager) GetImplicitRoles(name string, domain ...string) []string {
	visited := make(map[string]bool)
	var result []string
	rm.collectImplicitRoles(rm.buildKey(name, domain), visited, &result, 0)

	implicit := make([]string, 0, len(result))
	for _, r := range result {
		implicit = append(implicit, rm.stripDomain(r, domain...))
	}
	return implicit
}

// GetImplicitUsers 递归获取所有间接继承指定角色的用户列表（支持域隔离）
// 反向递归：找出所有直接或间接继承 name 角色的用户
func (rm *RoleManager) GetImplicitUsers(name string, domain ...string) []string {
	visited := make(map[string]bool)
	var result []string
	rm.collectImplicitUsers(rm.buildKey(name, domain), visited, &result, 0)

	implicit := make([]string, 0, len(result))
	for _, u := range result {
		implicit = append(implicit, rm.stripDomain(u, domain...))
	}
	return implicit
}

// GetDomains 获取指定角色所属的所有域
func (rm *RoleManager) GetDomains(name string) []string {
	return rm.hierarchy.GetDomains(name)
}

// GetAllDomains 获取所有域列表
func (rm *RoleManager) GetAllDomains() []string {
	return rm.hierarchy.GetAllDomains()
}

// DeleteDomain 删除指定域的所有角色关系
// 同时清理该域相关的所有缓存条目
func (rm *RoleManager) DeleteDomain(domain string) {
	rm.hierarchy.DeleteDomain(domain)
	rm.cache.Range(func(key, _ interface{}) bool {
		if strings.Contains(key.(string), domain+":") {
			rm.cache.Delete(key)
		}
		return true
	})
	rm.nameIndex.Range(func(key, _ interface{}) bool {
		if strings.Contains(key.(string), domain+":") {
			rm.nameIndex.Delete(key)
		}
		return true
	})
	rm.logger.InfoKV("Domain deleted", "domain", domain)
}

// Clear 清空所有角色关系和缓存
// 通常在重新加载策略时调用
func (rm *RoleManager) Clear() {
	rm.hierarchy.Clear()
	rm.cache = sync.Map{}
	rm.nameIndex = sync.Map{}
	rm.logger.DebugMsg("Role manager cleared")
}

// SetMaxDepth 设置递归查询最大深度
// 默认值为 10，超过此深度的继承链将被截断
// 适用于角色继承层级特别深的场景
func (rm *RoleManager) SetMaxDepth(depth int) {
	rm.maxDepth = depth
}

// GetHierarchy 获取底层角色层级管理器
// 用于需要直接操作 RoleHierarchy 的场景（如批量重建角色关系）
func (rm *RoleManager) GetHierarchy() *RoleHierarchy {
	return rm.hierarchy
}

func (rm *RoleManager) collectImplicitRoles(key string, visited map[string]bool, result *[]string, depth int) {
	if visited[key] || depth >= rm.maxDepth {
		return
	}
	visited[key] = true

	roles := rm.hierarchy.GetRoles(key)
	for _, r := range roles {
		*result = append(*result, r)
		rm.collectImplicitRoles(r, visited, result, depth+1)
	}
}

func (rm *RoleManager) collectImplicitUsers(key string, visited map[string]bool, result *[]string, depth int) {
	if visited[key] || depth >= rm.maxDepth {
		return
	}
	visited[key] = true

	users := rm.hierarchy.GetUsers(key)
	for _, u := range users {
		*result = append(*result, u)
		rm.collectImplicitUsers(u, visited, result, depth+1)
	}
}

func (rm *RoleManager) buildKey(name string, domain []string) string {
	if len(domain) > 0 {
		return domain[0] + ":" + name
	}
	return name
}

func (rm *RoleManager) buildCacheKey(name1, name2 string, domain ...string) string {
	if len(domain) > 0 {
		return domain[0] + ":" + name1 + "->" + name2
	}
	return name1 + "->" + name2
}

func (rm *RoleManager) stripDomain(key string, domain ...string) string {
	if len(domain) > 0 {
		prefix := domain[0] + ":"
		return strings.TrimPrefix(key, prefix)
	}
	return key
}

// addNameIndex 将 cacheKey 关联到指定 name，用于精准缓存失效
func (rm *RoleManager) addNameIndex(name, cacheKey string, domain ...string) {
	indexKey := rm.buildKey(name, domain)
	val, _ := rm.nameIndex.LoadOrStore(indexKey, &sync.Map{})
	keySet := val.(*sync.Map)
	keySet.Store(cacheKey, struct{}{})
}

// invalidateCache 精准失效与指定 name 相关的缓存条目
// 使用 nameIndex 索引直接定位相关缓存键，避免全量遍历
func (rm *RoleManager) invalidateCache(name string, domain ...string) {
	indexKey := rm.buildKey(name, domain)

	// 精准删除：通过 nameIndex 找到所有关联的 cacheKey
	if val, ok := rm.nameIndex.Load(indexKey); ok {
		keySet := val.(*sync.Map)
		keySet.Range(func(key, _ interface{}) bool {
			rm.cache.Delete(key)
			return true
		})
		// 清空 nameIndex 中该 name 的条目
		rm.nameIndex.Delete(indexKey)
	}
}
