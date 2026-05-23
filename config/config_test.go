/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 10:41:50
 * @FilePath: \go-casbin\config\config_test.go
 * @Description: 测试配置加载与解析
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestConfig() *Config {
	return NewConfig(logger.NewLogger())
}

func TestNewConfig(t *testing.T) {
	c := newTestConfig()
	assert.NotNil(t, c)
}

func TestConfig_SetAndGet(t *testing.T) {
	c := newTestConfig()
	c.Set("key1", "value1")
	assert.Equal(t, "value1", c.Get("key1"))
	assert.Equal(t, "", c.Get("nonexistent"))
}

func TestConfig_GetDefault(t *testing.T) {
	c := newTestConfig()
	c.Set("key1", "value1")
	assert.Equal(t, "value1", c.GetDefault("key1", "default"))
	assert.Equal(t, "default", c.GetDefault("nonexistent", "default"))
}

func TestConfig_Has(t *testing.T) {
	c := newTestConfig()
	c.Set("key1", "value1")
	assert.True(t, c.Has("key1"))
	assert.False(t, c.Has("nonexistent"))
}

func TestConfig_GetAll(t *testing.T) {
	c := newTestConfig()
	c.Set("key1", "value1")
	c.Set("key2", "value2")

	all := c.GetAll()
	assert.Equal(t, "value1", all["key1"])
	assert.Equal(t, "value2", all["key2"])

	// 返回的是副本，修改不影响原数据
	all["key1"] = "modified"
	assert.Equal(t, "value1", c.Get("key1"))
}

func TestConfig_Keys(t *testing.T) {
	c := newTestConfig()
	c.Set("key1", "value1")
	c.Set("key2", "value2")

	keys := c.Keys()
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "key1")
	assert.Contains(t, keys, "key2")
}

func TestConfig_Parse(t *testing.T) {
	c := newTestConfig()
	text := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

# 注释行应被忽略
key1 = value1
key2 = value2
`
	c.parse(text)

	assert.Equal(t, "sub, obj, act", c.Get("r"))
	assert.Equal(t, "sub, obj, act", c.Get("p"))
	assert.Equal(t, "value1", c.Get("key1"))
	assert.Equal(t, "value2", c.Get("key2"))
}

func TestConfig_Parse_SkipsInvalidLines(t *testing.T) {
	c := newTestConfig()
	text := `
key1 = value1
invalid_line
= value_without_key
key2 = value2
`
	c.parse(text)

	assert.Equal(t, "value1", c.Get("key1"))
	assert.Equal(t, "value2", c.Get("key2"))
	assert.Equal(t, "", c.Get("invalid_line"))
}

func TestLoadFromString(t *testing.T) {
	c, err := LoadFromString("key1 = value1", logger.NewLogger())
	require.NoError(t, err)
	assert.Equal(t, "value1", c.Get("key1"))
}

func TestLoadFromPath(t *testing.T) {
	// 创建临时配置文件
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.conf")
	content := "key1 = value1\nkey2 = value2"
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	c, err := LoadFromPath(tmpFile, logger.NewLogger())
	require.NoError(t, err)
	assert.Equal(t, "value1", c.Get("key1"))
	assert.Equal(t, "value2", c.Get("key2"))
}

func TestLoadFromPath_FileNotFound(t *testing.T) {
	_, err := LoadFromPath("/nonexistent/path/config.conf", logger.NewLogger())
	assert.Error(t, err)
}

func TestConfig_ConcurrentAccess(t *testing.T) {
	c := newTestConfig()
	done := make(chan struct{})

	// 并发读写
	for i := 0; i < 50; i++ {
		go func(i int) {
			c.Set("key", "value")
			_ = c.Get("key")
			_ = c.Has("key")
			_ = c.GetAll()
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}
