/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\pubsub_test.go
 * @Description: 分布式策略变更通知测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== ChangeEvent 测试 ====================

func TestNewChangeEvent(t *testing.T) {
	event := NewChangeEvent(EventTypePolicyAdded, "p", "node-1")
	assert.Equal(t, EventTypePolicyAdded, event.Type)
	assert.Equal(t, "p", event.PType)
	assert.Equal(t, "node-1", event.Source)
	assert.NotZero(t, event.Timestamp)
}

// ==================== NotifierConfig 测试 ====================

func TestDefaultNotifierConfig(t *testing.T) {
	config := DefaultNotifierConfig()
	assert.Equal(t, "casbin:policy:changes", config.Channel)
	assert.Equal(t, "unknown", config.Source)
	assert.Equal(t, 256, config.BufferSize)
	assert.Equal(t, 3, config.RetryCount)
	assert.Equal(t, time.Second, config.RetryInterval)
}

func TestNotifierOptions(t *testing.T) {
	config := DefaultNotifierConfig()
	WithChannel("custom-channel")(config)
	WithSource("node-1")(config)
	WithBufferSize(512)(config)
	WithRetry(2*time.Second, 5)(config)

	assert.Equal(t, "custom-channel", config.Channel)
	assert.Equal(t, "node-1", config.Source)
	assert.Equal(t, 512, config.BufferSize)
	assert.Equal(t, 2*time.Second, config.RetryInterval)
	assert.Equal(t, 5, config.RetryCount)
}

func TestNotifierOptions_EmptyValues(t *testing.T) {
	config := DefaultNotifierConfig()
	WithChannel("")(config)
	WithSource("")(config)
	WithBufferSize(0)(config)
	WithRetry(0, 0)(config)

	assert.Equal(t, "casbin:policy:changes", config.Channel)
	assert.Equal(t, "unknown", config.Source)
	assert.Equal(t, 256, config.BufferSize)
}

// ==================== LocalNotifier 测试 ====================

func TestLocalNotifier_PublishSubscribe(t *testing.T) {
	notifier := NewLocalNotifier(WithSource("test-node"))

	received := make([]*ChangeEvent, 0)
	err := notifier.Subscribe(context.Background(), func(event *ChangeEvent) {
		received = append(received, event)
	})
	require.NoError(t, err)

	event := NewChangeEvent(EventTypePolicyAdded, "p", "test-node")
	event.NewPolicy = []string{"alice", "data1", "read"}

	err = notifier.Publish(context.Background(), event)
	require.NoError(t, err)
	assert.Len(t, received, 1)
	assert.Equal(t, "test-node", received[0].Source)
}

func TestLocalNotifier_Unsubscribe(t *testing.T) {
	notifier := NewLocalNotifier()

	err := notifier.Subscribe(context.Background(), func(event *ChangeEvent) {})
	require.NoError(t, err)

	err = notifier.Unsubscribe()
	require.NoError(t, err)

	// Unsubscribe 后 handlers 为 nil，Publish 不 panic
	event := NewChangeEvent(EventTypePolicyAdded, "p", "test")
	err = notifier.Publish(context.Background(), event)
	require.NoError(t, err)
}

func TestLocalNotifier_Close(t *testing.T) {
	notifier := NewLocalNotifier()
	err := notifier.Close()
	require.NoError(t, err)
}

// ==================== NotifierHelper 测试 ====================

func TestNotifierHelper_PublishPolicyAdded(t *testing.T) {
	published := make([]*ChangeEvent, 0)
	helper := NotifierHelper{
		Publisher: func(ctx context.Context, event *ChangeEvent) error {
			published = append(published, event)
			return nil
		},
		Source: "helper-test",
	}

	err := helper.PublishPolicyAdded(context.Background(), "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	assert.Len(t, published, 1)
	assert.Equal(t, EventTypePolicyAdded, published[0].Type)
	assert.Equal(t, "helper-test", published[0].Source)
}

func TestNotifierHelper_PublishPolicyRemoved(t *testing.T) {
	published := make([]*ChangeEvent, 0)
	helper := NotifierHelper{
		Publisher: func(ctx context.Context, event *ChangeEvent) error {
			published = append(published, event)
			return nil
		},
		Source: "helper-test",
	}

	err := helper.PublishPolicyRemoved(context.Background(), "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	assert.Equal(t, EventTypePolicyRemoved, published[0].Type)
}

func TestNotifierHelper_PublishPolicyUpdated(t *testing.T) {
	published := make([]*ChangeEvent, 0)
	helper := NotifierHelper{
		Publisher: func(ctx context.Context, event *ChangeEvent) error {
			published = append(published, event)
			return nil
		},
		Source: "helper-test",
	}

	err := helper.PublishPolicyUpdated(context.Background(), "p", []string{"alice", "data1", "read"}, []string{"alice", "data2", "write"})
	require.NoError(t, err)
	assert.Equal(t, EventTypePolicyUpdated, published[0].Type)
}

func TestNotifierHelper_PublishPolicyReload(t *testing.T) {
	published := make([]*ChangeEvent, 0)
	helper := NotifierHelper{
		Publisher: func(ctx context.Context, event *ChangeEvent) error {
			published = append(published, event)
			return nil
		},
		Source: "helper-test",
	}

	err := helper.PublishPolicyReload(context.Background())
	require.NoError(t, err)
	assert.Equal(t, EventTypePolicyReload, published[0].Type)
}
