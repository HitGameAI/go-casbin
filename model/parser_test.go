/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\parser_test.go
 * @Description: 模型解析器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseModelFromText(t *testing.T) {
	assertions, err := ParseModelFromText(testModelText)
	require.NoError(t, err)
	assert.NotNil(t, assertions["r"])
	assert.NotNil(t, assertions["p"])
}

func TestParseModelFromText_Comments(t *testing.T) {
	text := `
# This is a comment
[r]
r = sub, obj, act

[p]
p = sub, obj, act

[e]
e = some(where (p.eft == allow))

[m]
m = r.sub == p.sub
`
	assertions, err := ParseModelFromText(text)
	require.NoError(t, err)
	assert.NotNil(t, assertions["r"])
}

func TestParseSectionName(t *testing.T) {
	assert.Equal(t, "r", ParseSectionName("[r]"))
	assert.Equal(t, "p2", ParseSectionName("[p2]"))
	assert.Equal(t, "", ParseSectionName("r"))
}

func TestSplitAssertionKey(t *testing.T) {
	section, name := SplitAssertionKey("r")
	assert.Equal(t, "r", section)
	assert.Equal(t, "r", name)

	section, name = SplitAssertionKey("p_2")
	assert.Equal(t, "p", section)
	assert.Equal(t, "2", name)

	// 没有 _ 分隔时，section 和 name 相同
	section, name = SplitAssertionKey("p2")
	assert.Equal(t, "p2", section)
	assert.Equal(t, "p2", name)
}
