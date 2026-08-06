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

func TestPolicyWatcher_CheckFileChange_StatError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	err := os.WriteFile(path, []byte("p, alice, data1, read\n"), 0644)
	require.NoError(t, err)

	pw := NewPolicyWatcher(path, 100*time.Millisecond, logger.NewLogger())
	err = pw.Start()
	require.NoError(t, err)
	defer pw.Stop()

	// 等待 watcher 完成初始启动
	time.Sleep(200 * time.Millisecond)

	// 删除文件，使 checkFileChange 中的 os.Stat 失败
	_ = os.Remove(path)

	// 等待至少一个检查周期，确保 checkFileChange 被调用并进入 stat 错误分支
	time.Sleep(300 * time.Millisecond)

	// 验证 watcher 仍在运行（stat 错误不会停止 watcher）
	pw.mu.Lock()
	running := pw.running
	pw.mu.Unlock()
	assert.True(t, running)
}

func TestPolicyWatcher_CallbackPanic(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	err := os.WriteFile(path, []byte("p, alice, data1, read\n"), 0644)
	require.NoError(t, err)

	pw := NewPolicyWatcher(path, 100*time.Millisecond, logger.NewLogger())

	// 注册一个会 panic 的回调
	panicRecovered := make(chan struct{}, 1)
	pw.AddCallback(func() {
		panic("test panic")
	})
	// 注册一个正常回调验证后续回调仍能执行
	normalCalled := make(chan struct{}, 1)
	pw.AddCallback(func() {
		select {
		case normalCalled <- struct{}{}:
		default:
		}
	})

	err = pw.Start()
	require.NoError(t, err)
	defer pw.Stop()

	// 等待 watcher 启动
	time.Sleep(200 * time.Millisecond)

	// 修改文件触发回调
	newTime := time.Now().Add(1 * time.Second)
	_ = os.Chtimes(path, newTime, newTime)
	_ = os.WriteFile(path, []byte("p, bob, data2, write\n"), 0644)

	// 等待回调执行（panic 应被 RecoverToError 恢复）
	time.Sleep(500 * time.Millisecond)

	// panic 被恢复后，正常回调仍应被调用
	select {
	case <-normalCalled:
		// 成功
	case <-time.After(3 * time.Second):
		t.Fatal("normal callback was not triggered after panic recovery")
	}

	// 确保 panicRecovered 通道不会阻塞（仅用于语义标记）
	select {
	case <-panicRecovered:
	default:
	}
}
