/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\watcher.go
 * @Description: 策略文件变更监控器
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// WatcherCallback 策略文件变更回调函数
type WatcherCallback func()

// PolicyWatcher 策略文件变更监控器
// 通过定时检查文件修改时间来检测策略文件变更
// 文件变更后触发所有注册的回调函数（通常执行 ReloadPolicy）
// 适用于单机文件适配器场景，分布式场景请使用 PolicyNotifier
type PolicyWatcher struct {
	filePath    string            // 监控的策略文件路径
	interval    time.Duration     // 检查间隔
	callbacks   []WatcherCallback // 变更回调列表
	stopCh      chan struct{}     // 停止信号通道
	workerPool  *syncx.WorkerPool // 协程池（并发执行回调）
	logger      logger.ILogger    // 日志记录器
	mu          sync.Mutex        // 保护 callbacks 和 running
	lastModTime time.Time         // 上次文件修改时间
	running     bool              // 是否正在运行
}

// NewPolicyWatcher 创建策略文件变更监控器
// filePath: 策略文件路径
// interval: 检查间隔，默认 200ms
// log: 日志记录器
func NewPolicyWatcher(filePath string, interval time.Duration, log logger.ILogger) *PolicyWatcher {
	return &PolicyWatcher{
		filePath:   filePath,
		interval:   interval,
		callbacks:  make([]WatcherCallback, 0),
		stopCh:     make(chan struct{}),
		workerPool: syncx.NewWorkerPool(5, 20),
		logger:     log,
	}
}

// AddCallback 注册策略变更回调函数
func (pw *PolicyWatcher) AddCallback(cb WatcherCallback) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.callbacks = append(pw.callbacks, cb)
}

// Start 启动文件变更监控
// 记录初始修改时间，启动后台监控循环
func (pw *PolicyWatcher) Start() error {
	pw.mu.Lock()
	if pw.running {
		pw.mu.Unlock()
		return nil
	}
	pw.running = true
	pw.mu.Unlock()

	info, err := os.Stat(pw.filePath)
	if err != nil {
		return err
	}
	pw.lastModTime = info.ModTime()

	go pw.watchLoop()
	pw.logger.InfoKV("Policy watcher started", "path", pw.filePath, "interval", pw.interval)
	return nil
}

// Stop 停止文件变更监控
func (pw *PolicyWatcher) Stop() {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if !pw.running {
		return
	}

	close(pw.stopCh)
	pw.workerPool.Close()
	pw.running = false
	pw.logger.InfoMsg("Policy watcher stopped")
}

// watchLoop 监控循环，定时检查文件修改时间
func (pw *PolicyWatcher) watchLoop() {
	ticker := time.NewTicker(pw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-pw.stopCh:
			return
		case <-ticker.C:
			pw.checkFileChange()
		}
	}
}

// checkFileChange 检查文件是否发生变更
// 如果文件修改时间晚于上次记录，则触发所有回调
func (pw *PolicyWatcher) checkFileChange() {
	info, err := os.Stat(pw.filePath)
	if err != nil {
		pw.logger.WarnKV("Failed to stat policy file", "path", pw.filePath, "error", err.Error())
		return
	}

	if info.ModTime().After(pw.lastModTime) {
		pw.lastModTime = info.ModTime()
		pw.logger.InfoKV("Policy file changed", "path", pw.filePath)

		pw.mu.Lock()
		callbacks := make([]WatcherCallback, len(pw.callbacks))
		copy(callbacks, pw.callbacks)
		pw.mu.Unlock()

		for _, cb := range callbacks {
			cb := cb
			_ = pw.workerPool.Submit(context.Background(), func() {
				syncx.RecoverToError(nil, func(r interface{}) {
					cb()
				})
			})
		}
	}
}
