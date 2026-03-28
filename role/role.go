/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\role.go
 * @Description: 角色定义与接口
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

type Role interface {
	Name() string
	AddLink(name2 string)
	DeleteLink(name2 string)
	HasLink(name2 string) bool
	GetLinks() []string
}

type RoleNode struct {
	name  string
	links []string
}

func NewRoleNode(name string) *RoleNode {
	return &RoleNode{
		name:  name,
		links: make([]string, 0),
	}
}

func (rn *RoleNode) Name() string {
	return rn.name
}

func (rn *RoleNode) AddLink(name2 string) {
	for _, l := range rn.links {
		if l == name2 {
			return
		}
	}
	rn.links = append(rn.links, name2)
}

func (rn *RoleNode) DeleteLink(name2 string) {
	for i, l := range rn.links {
		if l == name2 {
			rn.links = append(rn.links[:i], rn.links[i+1:]...)
			return
		}
	}
}

func (rn *RoleNode) HasLink(name2 string) bool {
	for _, l := range rn.links {
		if l == name2 {
			return true
		}
	}
	return false
}

func (rn *RoleNode) GetLinks() []string {
	result := make([]string, len(rn.links))
	copy(result, rn.links)
	return result
}
