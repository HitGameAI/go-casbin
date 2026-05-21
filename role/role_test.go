/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\role_test.go
 * @Description: 角色节点测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRoleNode(t *testing.T) {
	node := NewRoleNode("admin")
	assert.Equal(t, "admin", node.Name())
	assert.Empty(t, node.GetLinks())
}

func TestRoleNode_AddLink(t *testing.T) {
	node := NewRoleNode("admin")
	node.AddLink("editor")
	assert.True(t, node.HasLink("editor"))
	assert.False(t, node.HasLink("viewer"))

	// 重复添加
	node.AddLink("editor")
	links := node.GetLinks()
	assert.Len(t, links, 1)
}

func TestRoleNode_DeleteLink(t *testing.T) {
	node := NewRoleNode("admin")
	node.AddLink("editor")
	node.AddLink("viewer")

	node.DeleteLink("editor")
	assert.False(t, node.HasLink("editor"))
	assert.True(t, node.HasLink("viewer"))

	// 删除不存在的
	node.DeleteLink("nonexistent")
}

func TestRoleNode_GetLinks_ReturnsCopy(t *testing.T) {
	node := NewRoleNode("admin")
	node.AddLink("editor")
	links := node.GetLinks()
	links[0] = "modified"
	assert.True(t, node.HasLink("editor"))
}
