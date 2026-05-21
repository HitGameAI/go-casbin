/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\adapter_test.go
 * @Description: 适配器接口及内置实现测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== MemoryAdapter 测试 ====================

func TestMemoryAdapter_CRUD(t *testing.T) {
	ma := NewMemoryAdapter()

	err := ma.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})
	require.NoError(t, err)

	policies, err := ma.LoadPolicy()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	err = ma.AddPolicy("p, carol, data3, exec")
	require.NoError(t, err)
	policies, _ = ma.LoadPolicy()
	assert.Len(t, policies, 3)

	err = ma.RemovePolicy("p, alice, data1, read")
	require.NoError(t, err)
	policies, _ = ma.LoadPolicy()
	assert.Len(t, policies, 2)
}

func TestMemoryAdapter_Batch(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read"})

	err := ma.AddPolicies([]string{"p, bob, data2, write", "p, carol, data3, exec"})
	require.NoError(t, err)

	err = ma.RemovePolicies([]string{"p, alice, data1, read", "p, bob, data2, write"})
	require.NoError(t, err)

	policies, _ := ma.LoadPolicy()
	assert.Len(t, policies, 1)
}

func TestMemoryAdapter_Update(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read"})

	err := ma.UpdatePolicy("p, alice, data1, read", "p, alice, data2, write")
	require.NoError(t, err)

	policies, _ := ma.LoadPolicy()
	assert.Equal(t, "p, alice, data2, write", policies[0])
}

func TestMemoryAdapter_Update_NotFound(t *testing.T) {
	ma := NewMemoryAdapter()
	err := ma.UpdatePolicy("p, nonexistent, data, act", "p, new, data, act")
	assert.Error(t, err)
}

func TestMemoryAdapter_UpdatePolicies(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	err := ma.UpdatePolicies([]string{"p, alice, data1, read"}, []string{"p, alice, data3, exec"})
	require.NoError(t, err)
}

func TestMemoryAdapter_UpdateFilteredPolicies(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	err := ma.UpdateFilteredPolicies([]string{"p, carol, data3, exec"}, 0, "alice")
	require.NoError(t, err)
}

func TestMemoryAdapter_LoadFilteredPolicy(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	result, err := ma.LoadFilteredPolicy([]string{"alice"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.True(t, ma.IsFiltered())
}

func TestMemoryAdapter_LoadFilteredPolicy_NonStringFilter(t *testing.T) {
	ma := NewMemoryAdapter()
	_ = ma.SavePolicy([]string{"p, alice, data1, read"})

	result, err := ma.LoadFilteredPolicy(42)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// ==================== FileAdapter 测试 ====================

func TestFileAdapter_CRUD(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")

	fa := NewFileAdapter(path)

	err := fa.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})
	require.NoError(t, err)

	policies, err := fa.LoadPolicy()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	err = fa.AddPolicy("p, carol, data3, exec")
	require.NoError(t, err)

	err = fa.RemovePolicy("p, alice, data1, read")
	require.NoError(t, err)

	policies, _ = fa.LoadPolicy()
	assert.Len(t, policies, 2)
}

func TestFileAdapter_Batch(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)

	_ = fa.SavePolicy([]string{"p, alice, data1, read"})

	err := fa.AddPolicies([]string{"p, bob, data2, write"})
	require.NoError(t, err)

	err = fa.RemovePolicies([]string{"p, alice, data1, read"})
	require.NoError(t, err)
}

func TestFileAdapter_Update(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)

	_ = fa.SavePolicy([]string{"p, alice, data1, read"})

	err := fa.UpdatePolicy("p, alice, data1, read", "p, alice, data2, write")
	require.NoError(t, err)

	policies, _ := fa.LoadPolicy()
	assert.Equal(t, "p, alice, data2, write", policies[0])
}

func TestFileAdapter_Update_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)
	_ = fa.SavePolicy([]string{"p, alice, data1, read"})

	err := fa.UpdatePolicy("p, nonexistent, data, act", "p, new, data, act")
	assert.Error(t, err)
}

func TestFileAdapter_UpdatePolicies(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)
	_ = fa.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	err := fa.UpdatePolicies([]string{"p, alice, data1, read"}, []string{"p, alice, data3, exec"})
	require.NoError(t, err)
}

func TestFileAdapter_UpdateFilteredPolicies(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)
	_ = fa.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	err := fa.UpdateFilteredPolicies([]string{"p, carol, data3, exec"}, 0, "alice")
	require.NoError(t, err)
}

func TestFileAdapter_LoadFilteredPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)
	_ = fa.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})

	result, err := fa.LoadFilteredPolicy([]string{"alice"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.True(t, fa.IsFiltered())
}

func TestFileAdapter_LoadFilteredPolicy_NonStringFilter(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	fa := NewFileAdapter(path)
	_ = fa.SavePolicy([]string{"p, alice, data1, read"})

	result, err := fa.LoadFilteredPolicy(42)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestFileAdapter_LoadPolicy_NotFound(t *testing.T) {
	fa := NewFileAdapter("/nonexistent/policy.csv")
	_, err := fa.LoadPolicy()
	assert.Error(t, err)
}

func TestFileAdapter_SavePolicy_Error(t *testing.T) {
	fa := NewFileAdapter("/nonexistent-dir/policy.csv")
	err := fa.SavePolicy([]string{"p, alice, data1, read"})
	assert.Error(t, err)
}

func TestFileAdapter_AddPolicy_Error(t *testing.T) {
	fa := NewFileAdapter("/nonexistent-dir/policy.csv")
	err := fa.AddPolicy("p, alice, data1, read")
	assert.Error(t, err)
}

func TestFileAdapter_Comments(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.csv")
	content := "# This is a comment\np, alice, data1, read\n\np, bob, data2, write\n"
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)

	fa := NewFileAdapter(path)
	policies, err := fa.LoadPolicy()
	require.NoError(t, err)
	assert.Len(t, policies, 2)
}

// ==================== 序列化工具测试 ====================

func TestSerializeDeserializePolicy(t *testing.T) {
	data := []string{"p, alice, data1, read"}
	encoded, err := SerializePolicy(data)
	require.NoError(t, err)

	decoded, err := DeserializePolicy[[]string](encoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}
