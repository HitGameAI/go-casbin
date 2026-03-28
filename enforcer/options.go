/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\options.go
 * @Description: 执行器配置选项（链式 API）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/retry"
)

type Options struct {
	modelPath     string
	policyPath    string
	modelText     string
	logger        logger.ILogger
	breaker       *breaker.Circuit
	retry         *retry.Retry
	autoSave      bool
	enabled       bool
	watcher       bool
	watchInterval time.Duration
}

func defaultOptions() *Options {
	return &Options{
		autoSave:      true,
		enabled:       true,
		watcher:       false,
		watchInterval: 5 * time.Second,
	}
}

type Option func(*Options)

func WithModelPath(path string) Option {
	return func(o *Options) {
		o.modelPath = path
	}
}

func WithPolicyPath(path string) Option {
	return func(o *Options) {
		o.policyPath = path
	}
}

func WithModelText(text string) Option {
	return func(o *Options) {
		o.modelText = text
	}
}

func WithLogger(log logger.ILogger) Option {
	return func(o *Options) {
		o.logger = log
	}
}

func WithBreaker(name string, config breaker.Config) Option {
	return func(o *Options) {
		o.breaker = breaker.New(name, config)
	}
}

func WithRetry(r *retry.Retry) Option {
	return func(o *Options) {
		o.retry = r
	}
}

func WithAutoSave(autoSave bool) Option {
	return func(o *Options) {
		o.autoSave = autoSave
	}
}

func WithEnabled(enabled bool) Option {
	return func(o *Options) {
		o.enabled = enabled
	}
}

func WithWatcher(enabled bool, interval ...time.Duration) Option {
	return func(o *Options) {
		o.watcher = enabled
		if len(interval) > 0 {
			o.watchInterval = interval[0]
		}
	}
}
