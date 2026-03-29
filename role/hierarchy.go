/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\hierarchy.go
 * @Description: 角色层级管理（含继承、循环检测、域支持）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

import (
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
)

// RoleHierarchy 角色层级管理器
// 维护角色之间的继承关系图，支持以下核心能力：
//   - 添加/删除角色继承链接（含循环检测，防止 A→B→A 死循环）
//   - 深度优先搜索（DFS）判断间接继承关系
//   - 多租户域支持（通过 "domain:name" 格式的键实现域隔离）
//   - 域级别的批量清理（删除整个域的所有角色关系）
//
// 内部使用 map[string]Role 存储所有角色节点，键为角色名称
// 多租户场景下键格式为 "tenant1:alice"，单租户场景直接使用 "alice"
type RoleHierarchy struct {
	allRoles map[string]Role // 角色节点映射表（key=角色名称，value=角色节点）
	logger   logger.ILogger  // 日志记录器
}

// NewRoleHierarchy 创建角色层级管理器
// log: 日志记录器，用于记录角色链接的添加/删除操作
func NewRoleHierarchy(log logger.ILogger) *RoleHierarchy {
	return &RoleHierarchy{
		allRoles: make(map[string]Role),
		logger:   log,
	}
}

// AddLink 添加角色继承链接
// name1 继承 name2（即 name1 → name2）
// 添加前会进行循环检测：如果 name2 已经能到达 name1，则添加后会形成环，返回错误
// 例如：admin → editor 已存在，再添加 editor → admin 会触发循环检测错误
func (rh *RoleHierarchy) AddLink(name1, name2 string) error {
	if rh.hasCycle(name1, name2) {
		return errors.NewRoleCycleDetectedError(name1, name2)
	}

	role1 := rh.getOrCreateRole(name1)
	rh.getOrCreateRole(name2)

	role1.AddLink(name2)
	rh.logger.DebugKV("Role link added", "from", name1, "to", name2)
	return nil
}

// DeleteLink 删除角色继承链接
// name1 不再继承 name2（即移除 name1 → name2 的直接继承关系）
// 如果角色不存在则静默返回
func (rh *RoleHierarchy) DeleteLink(name1, name2 string) {
	role1, ok := rh.allRoles[name1]
	if !ok {
		return
	}
	role1.DeleteLink(name2)
	rh.logger.DebugKV("Role link deleted", "from", name1, "to", name2)
}

// HasLink 检查角色继承关系（含间接继承）
// name1 == name2 时直接返回 true（自身继承自身）
// 否则通过 DFS 遍历继承链，判断 name1 是否直接或间接继承 name2
// 例如：admin → editor → viewer，HasLink("admin", "viewer") → true
func (rh *RoleHierarchy) HasLink(name1, name2 string) bool {
	if name1 == name2 {
		return true
	}

	role, ok := rh.allRoles[name1]
	if !ok {
		return false
	}

	return rh.hasLinkDFS(role, name2, make(map[string]bool))
}

// GetRoles 获取角色直接继承的角色列表
// 返回 name 角色的所有直接继承角色（不包含间接继承）
func (rh *RoleHierarchy) GetRoles(name string) []string {
	role, ok := rh.allRoles[name]
	if !ok {
		return nil
	}
	return role.GetLinks()
}

// GetUsers 获取继承指定角色的所有用户
// 反向查询：找出所有直接继承 name 角色的角色
// 例如：admin 继承 editor，则 GetUsers("editor") 返回 ["admin"]
func (rh *RoleHierarchy) GetUsers(name string) []string {
	var users []string
	for key, role := range rh.allRoles {
		if role.HasLink(name) {
			users = append(users, key)
		}
	}
	return users
}

// GetDomains 获取指定角色所属的所有域
// 通过扫描所有角色的键（格式 "domain:name"），提取 name 匹配的域
// 例如：键 "tenant1:alice" 和 "tenant2:alice" → 返回 ["tenant1", "tenant2"]
func (rh *RoleHierarchy) GetDomains(name string) []string {
	var domains []string
	seen := make(map[string]bool)

	for key := range rh.allRoles {
		if strings.Contains(key, ":") {
			parts := strings.SplitN(key, ":", 2)
			domain := parts[0]
			user := parts[1]
			if user == name && !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

// GetAllDomains 获取所有域列表
// 扫描所有角色键，提取不重复的域名称
func (rh *RoleHierarchy) GetAllDomains() []string {
	var domains []string
	seen := make(map[string]bool)

	for key := range rh.allRoles {
		if strings.Contains(key, ":") {
			domain := strings.SplitN(key, ":", 2)[0]
			if !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

// DeleteDomain 删除指定域的所有角色关系
// 分三步清理：
//  1. 删除域内角色对域外角色的继承链接
//  2. 删除域内所有角色节点
//  3. 删除域外角色对域内角色的继承链接
//
// 例如：DeleteDomain("tenant1") 会清理所有 "tenant1:xxx" 相关的节点和链接
func (rh *RoleHierarchy) DeleteDomain(domain string) {
	prefix := domain + ":"
	for key, role := range rh.allRoles {
		if strings.HasPrefix(key, prefix) {
			links := role.GetLinks()
			for _, link := range links {
				if !strings.HasPrefix(link, prefix) {
					role.DeleteLink(link)
				}
			}
		}
	}

	for key := range rh.allRoles {
		if strings.HasPrefix(key, prefix) {
			delete(rh.allRoles, key)
		}
	}

	for _, role := range rh.allRoles {
		links := role.GetLinks()
		for _, link := range links {
			if strings.HasPrefix(link, prefix) {
				role.DeleteLink(link)
			}
		}
	}
}

// Clear 清空所有角色关系
// 重置角色映射表，通常在重新加载策略时调用
func (rh *RoleHierarchy) Clear() {
	rh.allRoles = make(map[string]Role)
}

// getOrCreateRole 获取或创建角色节点
// 如果角色已存在则返回现有节点，否则创建新节点并存入映射表
func (rh *RoleHierarchy) getOrCreateRole(name string) Role {
	role, ok := rh.allRoles[name]
	if !ok {
		role = NewRoleNode(name)
		rh.allRoles[name] = role
	}
	return role
}

// hasLinkDFS 深度优先搜索判断间接继承关系
// 从 role 出发，沿继承链向下搜索 target
// visited 集合防止重复访问（处理环形引用的防御性编程）
func (rh *RoleHierarchy) hasLinkDFS(role Role, target string, visited map[string]bool) bool {
	if visited[role.Name()] {
		return false
	}
	visited[role.Name()] = true

	for _, link := range role.GetLinks() {
		if link == target {
			return true
		}
		if linkedRole, ok := rh.allRoles[link]; ok {
			if rh.hasLinkDFS(linkedRole, target, visited) {
				return true
			}
		}
	}
	return false
}

// hasCycle 循环检测
// 判断添加 from → to 链接后是否会形成环
// 如果 from == to（自环）或 to 已经能到达 from，则存在循环
func (rh *RoleHierarchy) hasCycle(from, to string) bool {
	if from == to {
		return true
	}
	return rh.HasLink(to, from)
}
