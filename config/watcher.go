/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\config\watcher.go
 * @Description: 配置热更新监控器（基于 cron）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package config

import (
	"os"
	"sync"
	"time"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
)

type ConfigChangeCallback func(config *Config)

type ConfigWatcher struct {
	config    *Config
	filePath  string
	interval  time.Duration
	callbacks []ConfigChangeCallback
	stopCh    chan struct{}
	logger    logger.ILogger
	mu        sync.Mutex
	running   bool
	lastMod   time.Time
}

func NewConfigWatcher(config *Config, filePath string, interval time.Duration, log logger.ILogger) *ConfigWatcher {
	return &ConfigWatcher{
		config:    config,
		filePath:  filePath,
		interval:  interval,
		callbacks: make([]ConfigChangeCallback, 0),
		stopCh:    make(chan struct{}),
		logger:    log,
	}
}

func (cw *ConfigWatcher) OnChange(cb ConfigChangeCallback) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.callbacks = append(cw.callbacks, cb)
}

func (cw *ConfigWatcher) Start() error {
	cw.mu.Lock()
	if cw.running {
		cw.mu.Unlock()
		return nil
	}
	cw.running = true
	cw.mu.Unlock()

	info, err := os.Stat(cw.filePath)
	if err != nil {
		return errors.NewConfigWatchFailedError(err.Error())
	}
	cw.lastMod = info.ModTime()

	go cw.watchLoop()
	cw.logger.InfoKV("Config watcher started", "path", cw.filePath, "interval", cw.interval)
	return nil
}

func (cw *ConfigWatcher) Stop() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if !cw.running {
		return
	}

	close(cw.stopCh)
	cw.running = false
	cw.logger.InfoMsg("Config watcher stopped")
}

func (cw *ConfigWatcher) watchLoop() {
	ticker := time.NewTicker(cw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-cw.stopCh:
			return
		case <-ticker.C:
			cw.checkChange()
		}
	}
}

func (cw *ConfigWatcher) checkChange() {
	info, err := os.Stat(cw.filePath)
	if err != nil {
		cw.logger.WarnKV("Failed to stat config file", "path", cw.filePath, "error", err.Error())
		return
	}

	if info.ModTime().After(cw.lastMod) {
		cw.lastMod = info.ModTime()

		if err := cw.config.Load(cw.filePath); err != nil {
			cw.logger.ErrorKV("Failed to reload config", "path", cw.filePath, "error", err.Error())
			return
		}

		cw.logger.InfoKV("Config file changed and reloaded", "path", cw.filePath)

		cw.mu.Lock()
		callbacks := make([]ConfigChangeCallback, len(cw.callbacks))
		copy(callbacks, cw.callbacks)
		cw.mu.Unlock()

		for _, cb := range callbacks {
			cb(cw.config)
		}
	}
}
