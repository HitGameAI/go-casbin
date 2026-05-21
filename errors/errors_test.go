/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\errors\errors_test.go
 * @Description: 错误类型测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModelErrors(t *testing.T) {
	err := NewModelInvalidError("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test")

	err = NewModelLoadFailedError("path")
	assert.Error(t, err)

	err = NewModelParseFailedError("syntax")
	assert.Error(t, err)

	err = NewModelValidationFailedError("missing section")
	assert.Error(t, err)

	err = NewModelSectionMissingError("r")
	assert.Error(t, err)
}

func TestPolicyErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"NotFound", NewPolicyNotFoundError("p")},
		{"AlreadyExists", NewPolicyAlreadyExistsError("p, alice, data1")},
		{"EffectDenied", NewPolicyEffectDeniedError("deny")},
		{"AdapterFailed", NewPolicyAdapterFailedError("conn")},
		{"CacheFailed", NewPolicyCacheFailedError("miss")},
		{"WatchFailed", NewPolicyWatchFailedError("nats")},
		{"LoadFailed", NewPolicyLoadFailedError("io")},
		{"SaveFailed", NewPolicySaveFailedError("disk")},
		{"AddFailed", NewPolicyAddFailedError("dup")},
		{"RemoveFailed", NewPolicyRemoveFailedError("not found")},
		{"UpdateFailed", NewPolicyUpdateFailedError("conflict")},
		{"ClearFailed", NewPolicyClearFailedError("lock")},
		{"ParseFailed", NewPolicyParseFailedError("format")},
		{"FilterFailed", NewPolicyFilterFailedError("field")},
		{"CountMismatch", NewPolicyCountMismatchError("3 vs 5")},
		{"BatchAddFailed", NewPolicyBatchAddFailedError("timeout")},
		{"BatchRemoveFailed", NewPolicyBatchRemoveFailedError("partial")},
		{"BatchUpdateFailed", NewPolicyBatchUpdateFailedError("rollback")},
		{"AutoMigrateFailed", NewPolicyAutoMigrateFailedError("table")},
		{"GetByTypeFailed", NewPolicyGetByTypeFailedError("p2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.err)
		})
	}
}

func TestRoleErrors(t *testing.T) {
	err := NewRoleNotFoundError("admin")
	assert.Error(t, err)

	err = NewRoleAlreadyExistsError("admin")
	assert.Error(t, err)

	err = NewRoleCycleDetectedError("a", "b")
	assert.Error(t, err)

	err = NewRoleHierarchyFailedError("depth")
	assert.Error(t, err)
}

func TestEnforcerErrors(t *testing.T) {
	err := NewEnforcerNotReadyError("loading")
	assert.Error(t, err)

	err = NewEnforcerDisabledError("maintenance")
	assert.Error(t, err)

	err = NewEnforcerMatcherFailedError("eval")
	assert.Error(t, err)

	err = NewEnforcerBreakerOpenError("circuit")
	assert.Error(t, err)

	err = NewEnforcerRetryExhaustedError("3 attempts")
	assert.Error(t, err)
}

func TestConfigErrors(t *testing.T) {
	err := NewConfigLoadFailedError("file")
	assert.Error(t, err)

	err = NewConfigWatchFailedError("fsnotify")
	assert.Error(t, err)

	err = NewConfigInvalidError("yaml")
	assert.Error(t, err)
}

func TestMonitorErrors(t *testing.T) {
	err := NewMonitorFailedError("health")
	assert.Error(t, err)
}

func TestWrapError(t *testing.T) {
	inner := NewModelInvalidError("test")
	wrapped := WrapError("context", inner)
	assert.Error(t, wrapped)
	assert.Contains(t, wrapped.Error(), "context")
}
