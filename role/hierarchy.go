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

type RoleHierarchy struct {
	allRoles map[string]Role
	logger   logger.ILogger
}

func NewRoleHierarchy(log logger.ILogger) *RoleHierarchy {
	return &RoleHierarchy{
		allRoles: make(map[string]Role),
		logger:   log,
	}
}

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

func (rh *RoleHierarchy) DeleteLink(name1, name2 string) {
	role1, ok := rh.allRoles[name1]
	if !ok {
		return
	}
	role1.DeleteLink(name2)
	rh.logger.DebugKV("Role link deleted", "from", name1, "to", name2)
}

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

func (rh *RoleHierarchy) GetRoles(name string) []string {
	role, ok := rh.allRoles[name]
	if !ok {
		return nil
	}
	return role.GetLinks()
}

func (rh *RoleHierarchy) GetUsers(name string) []string {
	var users []string
	for key, role := range rh.allRoles {
		if role.HasLink(name) {
			users = append(users, key)
		}
	}
	return users
}

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

func (rh *RoleHierarchy) Clear() {
	rh.allRoles = make(map[string]Role)
}

func (rh *RoleHierarchy) getOrCreateRole(name string) Role {
	role, ok := rh.allRoles[name]
	if !ok {
		role = NewRoleNode(name)
		rh.allRoles[name] = role
	}
	return role
}

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

func (rh *RoleHierarchy) hasCycle(from, to string) bool {
	if from == to {
		return true
	}
	return rh.HasLink(to, from)
}
