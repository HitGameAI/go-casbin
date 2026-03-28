/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\manager.go
 * @Description: 角色管理器（含域支持、隐式查询、缓存）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

import (
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

type RoleManager struct {
	hierarchy *RoleHierarchy
	cache     syncx.Map[string, bool]
	logger    logger.ILogger
	maxDepth  int
}

func NewRoleManager(log logger.ILogger) *RoleManager {
	return &RoleManager{
		hierarchy: NewRoleHierarchy(log),
		logger:    log,
		maxDepth:  10,
	}
}

func (rm *RoleManager) AddLink(name1, name2 string, domain ...string) error {
	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	if err := rm.hierarchy.AddLink(n1, n2); err != nil {
		return errors.WrapError("AddLink", err)
	}

	rm.invalidateCache(name1, domain...)
	rm.logger.InfoKV("Role link added", "name1", name1, "name2", name2)
	return nil
}

func (rm *RoleManager) DeleteLink(name1, name2 string, domain ...string) {
	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	rm.hierarchy.DeleteLink(n1, n2)
	rm.invalidateCache(name1, domain...)
	rm.logger.InfoKV("Role link deleted", "name1", name1, "name2", name2)
}

func (rm *RoleManager) HasLink(name1, name2 string, domain ...string) bool {
	cacheKey := rm.buildCacheKey(name1, name2, domain...)
	if result, ok := rm.cache.Load(cacheKey); ok {
		return result
	}

	n1 := rm.buildKey(name1, domain)
	n2 := rm.buildKey(name2, domain)

	result := rm.hierarchy.HasLink(n1, n2)
	rm.cache.Store(cacheKey, result)
	return result
}

func (rm *RoleManager) GetRoles(name string, domain ...string) []string {
	n := rm.buildKey(name, domain)
	roles := rm.hierarchy.GetRoles(n)

	result := make([]string, 0, len(roles))
	for _, r := range roles {
		result = append(result, rm.stripDomain(r, domain...))
	}
	return result
}

func (rm *RoleManager) GetUsers(name string, domain ...string) []string {
	n := rm.buildKey(name, domain)
	users := rm.hierarchy.GetUsers(n)

	result := make([]string, 0, len(users))
	for _, u := range users {
		result = append(result, rm.stripDomain(u, domain...))
	}
	return result
}

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

func (rm *RoleManager) GetDomains(name string) []string {
	return rm.hierarchy.GetDomains(name)
}

func (rm *RoleManager) GetAllDomains() []string {
	return rm.hierarchy.GetAllDomains()
}

func (rm *RoleManager) DeleteDomain(domain string) {
	rm.hierarchy.DeleteDomain(domain)
	rm.cache.Range(func(key string, value bool) bool {
		if strings.Contains(key, domain+":") {
			rm.cache.Delete(key)
		}
		return true
	})
	rm.logger.InfoKV("Domain deleted", "domain", domain)
}

func (rm *RoleManager) Clear() {
	rm.hierarchy.Clear()
	rm.cache.Range(func(key string, value bool) bool {
		rm.cache.Delete(key)
		return true
	})
	rm.logger.DebugMsg("Role manager cleared")
}

func (rm *RoleManager) SetMaxDepth(depth int) {
	rm.maxDepth = depth
}

func (rm *RoleManager) GetHierarchy() *RoleHierarchy {
	return rm.hierarchy
}

func (rm *RoleManager) collectImplicitRoles(key string, visited map[string]bool, result *[]string, depth int) {
	if visited[key] || depth > rm.maxDepth {
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
	if visited[key] || depth > rm.maxDepth {
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

func (rm *RoleManager) invalidateCache(name string, domain ...string) {
	prefix := rm.buildKey(name, domain)
	rm.cache.Range(func(key string, value bool) bool {
		if strings.Contains(key, prefix) {
			rm.cache.Delete(key)
		}
		return true
	})
}
