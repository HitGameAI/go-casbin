/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\watcher_test.go
 * @Description: 策略文件变更监控器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyWatcher_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	err := os.WriteFile(path, []byte("p, alice, data1, read\n"), 0644)
	require.NoError(t, err)

	pw := NewPolicyWatcher(path, 100*time.Millisecond, logger.NewLogger())

	err = pw.Start()
	require.NoError(t, err)

	// 重复 Start 不报错
	err = pw.Start()
	require.NoError(t, err)

	pw.Stop()

	// 重复 Stop 不 panic
	pw.Stop()
}

func TestPolicyWatcher_Start_FileNotFound(t *testing.T) {
	pw := NewPolicyWatcher("/nonexistent/policy.csv", 100*time.Millisecond, logger.NewLogger())
	err := pw.Start()
	assert.Error(t, err)
}

func TestPolicyWatcher_Callback(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	err := os.WriteFile(path, []byte("p, alice, data1, read\n"), 0644)
	require.NoError(t, err)

	pw := NewPolicyWatcher(path, 100*time.Millisecond, logger.NewLogger())

	called := make(chan struct{}, 1)
	pw.AddCallback(func() {
		select {
		case called <- struct{}{}:
		default:
		}
	})

	err = pw.Start()
	require.NoError(t, err)
	defer pw.Stop()

	// 等待 watcher 启动完成
	time.Sleep(300 * time.Millisecond)

	// 修改文件触发回调（需要确保修改时间有差异）
	// Windows 文件系统修改时间精度为 100ns，但有时需要更大的时间差
	time.Sleep(200 * time.Millisecond)

	// 使用 Chtimes 确保修改时间变化
	newTime := time.Now().Add(1 * time.Second)
	err = os.Chtimes(path, newTime, newTime)
	require.NoError(t, err)

	err = os.WriteFile(path, []byte("p, bob, data2, write\n"), 0644)
	require.NoError(t, err)

	select {
	case <-called:
		// 回调被触发
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not triggered within timeout")
	}
}

func TestPolicyWatcher_AddCallback(t *testing.T) {
	pw := NewPolicyWatcher("test.csv", 100*time.Millisecond, logger.NewLogger())
	pw.AddCallback(func() {})
	pw.AddCallback(func() {})
	assert.Len(t, pw.callbacks, 2)
}
