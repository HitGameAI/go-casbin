/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\loader_test.go
 * @Description: 模型加载器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadModelFromPath(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "model.conf")
	err := os.WriteFile(path, []byte(testModelText), 0644)
	require.NoError(t, err)

	assertions, err := LoadModelFromPath(path)
	require.NoError(t, err)
	assert.NotNil(t, assertions["r"])
}

func TestLoadModelFromPath_NotFound(t *testing.T) {
	_, err := LoadModelFromPath("/nonexistent/model.conf")
	assert.Error(t, err)
}

func TestLoadModelFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "model.conf")
	err := os.WriteFile(path, []byte(testModelText), 0644)
	require.NoError(t, err)

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	assertions, err := LoadModelFromFile(file)
	require.NoError(t, err)
	assert.NotNil(t, assertions["r"])
}

func TestLoadModelFromText(t *testing.T) {
	assertions, err := LoadModelFromText(testModelText)
	require.NoError(t, err)
	assert.NotNil(t, assertions["r"])
}

func TestNewModelFromPath(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "model.conf")
	err := os.WriteFile(path, []byte(testModelText), 0644)
	require.NoError(t, err)

	m, err := NewModelFromPath(path, newTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestNewModelFromPath_NotFound(t *testing.T) {
	_, err := NewModelFromPath("/nonexistent/model.conf", newTestLogger())
	assert.Error(t, err)
}

func TestLoadModelFromFile_StatError(t *testing.T) {
	// 使用已关闭的文件触发 Stat 错误
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "model.conf")
	err := os.WriteFile(path, []byte(testModelText), 0644)
	require.NoError(t, err)

	file, err := os.Open(path)
	require.NoError(t, err)
	file.Close()

	_, err = LoadModelFromFile(file)
	assert.Error(t, err)
}
