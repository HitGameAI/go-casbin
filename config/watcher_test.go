/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\config\watcher_test.go
 * @Description: 测试配置热更新监控器
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigWatcher(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	tmpFile := filepath.Join(t.TempDir(), "test.conf")
	err := os.WriteFile(tmpFile, []byte("key1 = value1"), 0644)
	require.NoError(t, err)

	cw := NewConfigWatcher(c, tmpFile, 100*time.Millisecond, logger.NewLogger())
	assert.NotNil(t, cw)
}

func TestConfigWatcher_StartAndStop(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	tmpFile := filepath.Join(t.TempDir(), "test.conf")
	err := os.WriteFile(tmpFile, []byte("key1 = value1"), 0644)
	require.NoError(t, err)

	cw := NewConfigWatcher(c, tmpFile, 100*time.Millisecond, logger.NewLogger())

	err = cw.Start()
	require.NoError(t, err)

	// 重复 Start 不应报错
	err = cw.Start()
	require.NoError(t, err)

	cw.Stop()

	// 重复 Stop 不应 panic
	cw.Stop()
}

func TestConfigWatcher_Start_FileNotFound(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	cw := NewConfigWatcher(c, "/nonexistent/path.conf", 100*time.Millisecond, logger.NewLogger())

	err := cw.Start()
	assert.Error(t, err)
}

func TestConfigWatcher_OnChange(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.conf")
	err := os.WriteFile(tmpFile, []byte("key1 = value1"), 0644)
	require.NoError(t, err)

	cw := NewConfigWatcher(c, tmpFile, 50*time.Millisecond, logger.NewLogger())

	changed := make(chan struct{}, 1)
	cw.OnChange(func(cfg *Config) {
		if cfg.Get("key1") == "value2" {
			changed <- struct{}{}
		}
	})

	err = cw.Start()
	require.NoError(t, err)
	defer cw.Stop()

	// 修改文件内容触发变更
	time.Sleep(100 * time.Millisecond)
	err = os.WriteFile(tmpFile, []byte("key1 = value2"), 0644)
	require.NoError(t, err)

	// 等待变更回调
	select {
	case <-changed:
		// 成功收到变更通知
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for config change callback")
	}
}

func TestConfigWatcher_CheckChange_FileDeleted(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.conf")
	err := os.WriteFile(tmpFile, []byte("key1 = value1"), 0644)
	require.NoError(t, err)

	cw := NewConfigWatcher(c, tmpFile, 50*time.Millisecond, logger.NewLogger())

	err = cw.Start()
	require.NoError(t, err)
	defer cw.Stop()

	// 删除文件后 checkChange 应处理 os.Stat 错误
	time.Sleep(100 * time.Millisecond)
	os.Remove(tmpFile)
	time.Sleep(200 * time.Millisecond)
	// 不应 panic
}

func TestConfigWatcher_CheckChange_InvalidContent(t *testing.T) {
	c := NewConfig(logger.NewLogger())
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.conf")
	err := os.WriteFile(tmpFile, []byte("key1 = value1"), 0644)
	require.NoError(t, err)

	cw := NewConfigWatcher(c, tmpFile, 50*time.Millisecond, logger.NewLogger())

	err = cw.Start()
	require.NoError(t, err)
	defer cw.Stop()

	// 写入无效内容后 checkChange 应处理 Load 错误
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(tmpFile, []byte("= invalid ="), 0644)
	time.Sleep(200 * time.Millisecond)
	// 不应 panic
}
