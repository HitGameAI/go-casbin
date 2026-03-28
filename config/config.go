/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\config\config.go
 * @Description: 配置加载与解析
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package config

import (
	"os"
	"strings"
	"sync"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/stringx"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

type Config struct {
	mu     sync.RWMutex
	data   map[string]string
	logger logger.ILogger
}

func NewConfig(log logger.ILogger) *Config {
	return &Config{
		data:   make(map[string]string),
		logger: log,
	}
}

func LoadFromPath(path string, log logger.ILogger) (*Config, error) {
	c := NewConfig(log)
	if err := c.Load(path); err != nil {
		return nil, err
	}
	return c, nil
}

func LoadFromString(text string, log logger.ILogger) (*Config, error) {
	c := NewConfig(log)
	c.parse(text)
	return c, nil
}

func (c *Config) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.NewConfigLoadFailedError(err.Error())
	}

	c.parse(string(data))
	c.logger.InfoKV("Config loaded", "path", path, "keys", len(c.data))
	return nil
}

func (c *Config) parse(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := stringx.New(strings.TrimSpace(parts[0])).ToLowerChain().Value()
		value := strings.TrimSpace(parts[1])
		c.data[key] = value
	}
}

func (c *Config) Get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data[key]
}

func (c *Config) GetDefault(key, defaultValue string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if val, ok := c.data[key]; ok {
		return val
	}
	return defaultValue
}

func (c *Config) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

func (c *Config) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.data[key]
	return ok
}

func (c *Config) GetAll() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]string, len(c.data))
	syncx.DeepCopy(c.data, &result)
	return result
}

func (c *Config) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.data))
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}
