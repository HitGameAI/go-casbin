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

type WatcherCallback func()

type PolicyWatcher struct {
	filePath    string
	interval    time.Duration
	callbacks   []WatcherCallback
	stopCh      chan struct{}
	workerPool  *syncx.WorkerPool
	logger      logger.ILogger
	mu          sync.Mutex
	lastModTime time.Time
	running     bool
}

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

func (pw *PolicyWatcher) AddCallback(cb WatcherCallback) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.callbacks = append(pw.callbacks, cb)
}

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
