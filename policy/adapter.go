/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\adapter.go
 * @Description: 适配器接口及内置实现 - 定义策略存储的标准接口，提供文件适配器和内存适配器
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-toolbox/pkg/serializer"
)

// ==================== 适配器接口定义 ====================

// Adapter 基础策略适配器接口
// 所有适配器必须实现这四个核心方法：加载、保存、添加、删除
type Adapter interface {
	LoadPolicy() ([]string, error)      // 从存储加载所有策略
	SavePolicy(policies []string) error // 保存所有策略到存储
	AddPolicy(line string) error        // 添加单条策略
	RemovePolicy(line string) error     // 删除单条策略
}

// FilteredAdapter 支持过滤加载的适配器接口
// 扩展 Adapter，增加按条件过滤加载策略的能力
type FilteredAdapter interface {
	Adapter
	LoadFilteredPolicy(filter interface{}) ([]string, error) // 按过滤条件加载策略
	IsFiltered() bool                                        // 返回是否已使用过滤加载
}

// BatchAdapter 支持批量操作的适配器接口
// 扩展 Adapter，增加批量添加和删除策略的能力，提升性能
type BatchAdapter interface {
	Adapter
	AddPolicies(lines []string) error    // 批量添加策略
	RemovePolicies(lines []string) error // 批量删除策略
}

// UpdatableAdapter 支持更新操作的适配器接口
// 扩展 Adapter，增加策略更新能力，包括单条更新、批量更新和过滤更新
type UpdatableAdapter interface {
	Adapter
	UpdatePolicy(oldLine, newLine string) error                                            // 更新单条策略
	UpdatePolicies(oldLines, newLines []string) error                                      // 批量更新策略
	UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error // 按过滤条件更新策略
}

// PTypeUpdatableAdapter 支持按策略类型更新操作的适配器接口
// 扩展 UpdatableAdapter，增加按策略类型更新的能力
// 适用于需要按策略类型更新 p 和 g 规则的场景
type PTypeUpdatableAdapter interface {
	Adapter
	UpdateFilteredPoliciesByPType(ptype string, newLines []string, fieldIndex int, fieldValues ...string) error
}

// ==================== 带 Context 的适配器接口 ====================
// 以下接口为适配器提供 context.Context 支持，用于超时控制和分布式链路追踪
// 适配器可同时实现非 ctx 和 WithCtx 两套接口，非 ctx 方法内部调用 WithCtx 并传入 context.Background()

// ContextAdapter 支持 Context 的基础适配器接口
// 扩展 Adapter，增加带 context 的 CRUD 方法
// 适用于需要超时控制、链路追踪或请求取消的场景
type ContextAdapter interface {
	Adapter
	LoadPolicyWithCtx(ctx context.Context) ([]string, error)        // 带上下文从存储加载所有策略
	SavePolicyWithCtx(ctx context.Context, policies []string) error // 带上下文保存所有策略到存储
	AddPolicyWithCtx(ctx context.Context, line string) error        // 带上下文添加单条策略
	RemovePolicyWithCtx(ctx context.Context, line string) error     // 带上下文删除单条策略
}

// FilteredContextAdapter 支持 Context 和过滤加载的适配器接口
// 扩展 ContextAdapter，增加带上下文的过滤加载能力
type FilteredContextAdapter interface {
	ContextAdapter
	LoadFilteredPolicyWithCtx(ctx context.Context, filter interface{}) ([]string, error) // 带上下文按过滤条件加载策略
	IsFiltered() bool                                                                    // 返回是否已使用过滤加载
}

// BatchContextAdapter 支持 Context 和批量操作的适配器接口
// 扩展 ContextAdapter，增加带上下文的批量操作能力
type BatchContextAdapter interface {
	ContextAdapter
	AddPoliciesWithCtx(ctx context.Context, lines []string) error    // 带上下文批量添加策略
	RemovePoliciesWithCtx(ctx context.Context, lines []string) error // 带上下文批量删除策略
}

// UpdatableContextAdapter 支持 Context 和更新操作的适配器接口
// 扩展 ContextAdapter，增加带上下文的策略更新能力
type UpdatableContextAdapter interface {
	ContextAdapter
	UpdatePolicyWithCtx(ctx context.Context, oldLine, newLine string) error                                            // 带上下文更新单条策略
	UpdatePoliciesWithCtx(ctx context.Context, oldLines, newLines []string) error                                      // 带上下文批量更新策略
	UpdateFilteredPoliciesWithCtx(ctx context.Context, newLines []string, fieldIndex int, fieldValues ...string) error // 带上下文按过滤条件更新策略
}

// PTypeUpdatableContextAdapter 支持 Context 和按策略类型更新操作的适配器接口
// 扩展 ContextAdapter，增加带上下文的按策略类型更新能力
// 适用于需要按策略类型更新 p 和 g 规则的场景
type PTypeUpdatableContextAdapter interface {
	ContextAdapter
	UpdateFilteredPoliciesByPTypeWithCtx(ctx context.Context, ptype string, newLines []string, fieldIndex int, fieldValues ...string) error
}

// FullAdapter 全功能适配器接口
// 组合了所有适配器接口（含 WithCtx），表示适配器支持全部操作能力
// GORM 适配器和 Redis 适配器均实现了此接口
type FullAdapter interface {
	ContextAdapter
	FilteredContextAdapter
	BatchContextAdapter
	UpdatableContextAdapter
}

// TransactionalAdapter 支持事务的适配器接口
// 扩展 Adapter，增加事务执行能力
// 适配器实现此接口后，enforcer 的事务方法可以确保多个操作在同一个数据库事务中执行
// 如果适配器不支持事务，enforcer 会回退到非事务模式
type TransactionalAdapter interface {
	Adapter
	ExecuteInTransaction(ctx context.Context, fn func(Adapter) error) error
}

// ==================== 文件适配器 ====================

// FileAdapter 基于文件的策略适配器
// 策略存储在文本文件中，每行一条策略，支持 # 注释
// 适用于开发环境和小规模部署
type FileAdapter struct {
	filePath string // 策略文件路径
	filtered bool   // 是否已使用过滤加载
}

// NewFileAdapter 创建文件适配器
func NewFileAdapter(filePath string) *FileAdapter {
	return &FileAdapter{filePath: filePath}
}

// LoadPolicy 从文件加载所有策略
// 跳过空行和以 # 开头的注释行
func (fa *FileAdapter) LoadPolicy() ([]string, error) {
	file, err := os.Open(fa.filePath)
	if err != nil {
		return nil, errors.NewPolicyAdapterFailedError(err.Error())
	}
	defer file.Close()

	var policies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			policies = append(policies, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.NewPolicyAdapterFailedError(err.Error())
	}

	return policies, nil
}

// SavePolicy 将所有策略保存到文件（覆盖写入）
func (fa *FileAdapter) SavePolicy(policies []string) error {
	file, err := os.Create(fa.filePath)
	if err != nil {
		return errors.NewPolicyAdapterFailedError(err.Error())
	}
	defer file.Close()

	for _, policy := range policies {
		if _, err := file.WriteString(policy + "\n"); err != nil {
			return errors.NewPolicyAdapterFailedError(err.Error())
		}
	}
	return nil
}

// AddPolicy 追加单条策略到文件末尾
func (fa *FileAdapter) AddPolicy(line string) error {
	file, err := os.OpenFile(fa.filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return errors.NewPolicyAdapterFailedError(err.Error())
	}
	defer file.Close()

	if _, err := file.WriteString(line + "\n"); err != nil {
		return errors.NewPolicyAdapterFailedError(err.Error())
	}
	return nil
}

// RemovePolicy 从文件中删除单条策略
// 先加载所有策略，过滤掉目标策略，再覆盖写入
func (fa *FileAdapter) RemovePolicy(line string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	var filtered []string
	for _, p := range policies {
		if strings.TrimSpace(p) != strings.TrimSpace(line) {
			filtered = append(filtered, p)
		}
	}

	return fa.SavePolicy(filtered)
}

// AddPolicies 批量追加策略到文件末尾
func (fa *FileAdapter) AddPolicies(lines []string) error {
	file, err := os.OpenFile(fa.filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return errors.NewPolicyAdapterFailedError(err.Error())
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			return errors.NewPolicyAdapterFailedError(err.Error())
		}
	}
	return nil
}

// RemovePolicies 批量从文件中删除策略
func (fa *FileAdapter) RemovePolicies(lines []string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	removeSet := make(map[string]bool, len(lines))
	for _, l := range lines {
		removeSet[strings.TrimSpace(l)] = true
	}

	var filtered []string
	for _, p := range policies {
		if !removeSet[strings.TrimSpace(p)] {
			filtered = append(filtered, p)
		}
	}

	return fa.SavePolicy(filtered)
}

// UpdatePolicy 更新文件中的单条策略
func (fa *FileAdapter) UpdatePolicy(oldLine, newLine string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	for i, p := range policies {
		if strings.TrimSpace(p) == strings.TrimSpace(oldLine) {
			policies[i] = newLine
			return fa.SavePolicy(policies)
		}
	}

	return errors.NewPolicyNotFoundError(oldLine)
}

// UpdatePolicies 批量更新文件中的策略
func (fa *FileAdapter) UpdatePolicies(oldLines, newLines []string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	oldSet := make(map[string]string, len(oldLines))
	for i, old := range oldLines {
		oldSet[strings.TrimSpace(old)] = newLines[i]
	}

	for i, p := range policies {
		if newP, ok := oldSet[strings.TrimSpace(p)]; ok {
			policies[i] = newP
		}
	}

	return fa.SavePolicy(policies)
}

// UpdateFilteredPolicies 按过滤条件更新文件中的策略
// 先移除匹配的旧策略，再追加新策略
func (fa *FileAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	var result []string
	for _, p := range policies {
		tokens := strings.Split(p, ",")
		match := true
		for i, val := range fieldValues {
			idx := fieldIndex + i
			if idx >= len(tokens) || strings.TrimSpace(tokens[idx]) != val {
				match = false
				break
			}
		}
		if !match {
			result = append(result, p)
		}
	}

	result = append(result, newLines...)
	return fa.SavePolicy(result)
}

// UpdateFilteredPoliciesByPType 按策略类型更新文件中的策略
// 先移除匹配的旧策略，再追加新策略
// 适用于需要按策略类型更新 p 和 g 规则的场景
func (fa *FileAdapter) UpdateFilteredPoliciesByPType(ptype string, newLines []string, fieldIndex int, fieldValues ...string) error {
	policies, err := fa.LoadPolicy()
	if err != nil {
		return err
	}

	var result []string
	for _, p := range policies {
		tokens := strings.Split(p, ",")
		if len(tokens) == 0 || strings.TrimSpace(tokens[0]) != ptype {
			result = append(result, p)
			continue
		}
		match := true
		for i, val := range fieldValues {
			idx := fieldIndex + i + 1
			if idx >= len(tokens) || strings.TrimSpace(tokens[idx]) != val {
				match = false
				break
			}
		}
		if !match {
			result = append(result, p)
		}
	}

	result = append(result, newLines...)
	return fa.SavePolicy(result)
}

// LoadFilteredPolicy 按过滤条件从文件加载策略
func (fa *FileAdapter) LoadFilteredPolicy(filter interface{}) ([]string, error) {
	fa.filtered = true
	policies, err := fa.LoadPolicy()
	if err != nil {
		return nil, err
	}

	filterValues, ok := filter.([]string)
	if !ok {
		return policies, nil
	}

	var result []string
	for _, p := range policies {
		tokens := strings.Split(p, ",")
		match := true
		for _, fv := range filterValues {
			found := false
			for _, t := range tokens {
				if strings.TrimSpace(t) == fv {
					found = true
					break
				}
			}
			if !found {
				match = false
				break
			}
		}
		if match {
			result = append(result, p)
		}
	}
	return result, nil
}

// IsFiltered 返回是否已使用过滤加载
func (fa *FileAdapter) IsFiltered() bool {
	return fa.filtered
}

// ==================== 内存适配器 ====================

// MemoryAdapter 基于内存的策略适配器
// 策略存储在内存切片中，适用于测试和临时场景
// 重启后数据丢失，不支持持久化
type MemoryAdapter struct {
	policies []string // 策略列表
	filtered bool     // 是否已使用过滤加载
}

// NewMemoryAdapter 创建内存适配器
func NewMemoryAdapter() *MemoryAdapter {
	return &MemoryAdapter{
		policies: make([]string, 0),
	}
}

// LoadPolicy 从内存加载所有策略
func (ma *MemoryAdapter) LoadPolicy() ([]string, error) {
	return ma.policies, nil
}

// SavePolicy 保存所有策略到内存（覆盖）
func (ma *MemoryAdapter) SavePolicy(policies []string) error {
	ma.policies = make([]string, len(policies))
	copy(ma.policies, policies)
	return nil
}

// AddPolicy 添加单条策略到内存
func (ma *MemoryAdapter) AddPolicy(line string) error {
	ma.policies = append(ma.policies, line)
	return nil
}

// RemovePolicy 从内存中删除单条策略
func (ma *MemoryAdapter) RemovePolicy(line string) error {
	var filtered []string
	for _, p := range ma.policies {
		if strings.TrimSpace(p) != strings.TrimSpace(line) {
			filtered = append(filtered, p)
		}
	}
	ma.policies = filtered
	return nil
}

// AddPolicies 批量添加策略到内存
func (ma *MemoryAdapter) AddPolicies(lines []string) error {
	ma.policies = append(ma.policies, lines...)
	return nil
}

// RemovePolicies 批量从内存中删除策略
func (ma *MemoryAdapter) RemovePolicies(lines []string) error {
	removeSet := make(map[string]bool, len(lines))
	for _, l := range lines {
		removeSet[strings.TrimSpace(l)] = true
	}

	var filtered []string
	for _, p := range ma.policies {
		if !removeSet[strings.TrimSpace(p)] {
			filtered = append(filtered, p)
		}
	}
	ma.policies = filtered
	return nil
}

// UpdatePolicy 更新内存中的单条策略
func (ma *MemoryAdapter) UpdatePolicy(oldLine, newLine string) error {
	for i, p := range ma.policies {
		if strings.TrimSpace(p) == strings.TrimSpace(oldLine) {
			ma.policies[i] = newLine
			return nil
		}
	}
	return errors.NewPolicyNotFoundError(oldLine)
}

// UpdatePolicies 批量更新内存中的策略
func (ma *MemoryAdapter) UpdatePolicies(oldLines, newLines []string) error {
	oldSet := make(map[string]string, len(oldLines))
	for i, old := range oldLines {
		oldSet[strings.TrimSpace(old)] = newLines[i]
	}

	for i, p := range ma.policies {
		if newP, ok := oldSet[strings.TrimSpace(p)]; ok {
			ma.policies[i] = newP
		}
	}
	return nil
}

// UpdateFilteredPolicies 按过滤条件更新内存中的策略
func (ma *MemoryAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	var result []string
	for _, p := range ma.policies {
		tokens := strings.Split(p, ",")
		match := true
		for i, val := range fieldValues {
			idx := fieldIndex + i
			if idx >= len(tokens) || strings.TrimSpace(tokens[idx]) != val {
				match = false
				break
			}
		}
		if !match {
			result = append(result, p)
		}
	}

	result = append(result, newLines...)
	ma.policies = result
	return nil
}

// UpdateFilteredPoliciesByPType 按策略类型更新内存中的策略
// 先移除匹配的旧策略，再追加新策略
// 适用于需要按策略类型更新 p 和 g 规则的场景
func (ma *MemoryAdapter) UpdateFilteredPoliciesByPType(ptype string, newLines []string, fieldIndex int, fieldValues ...string) error {
	var result []string
	for _, p := range ma.policies {
		tokens := strings.Split(p, ",")
		if len(tokens) == 0 || strings.TrimSpace(tokens[0]) != ptype {
			result = append(result, p)
			continue
		}
		match := true
		for i, val := range fieldValues {
			idx := fieldIndex + i + 1
			if idx >= len(tokens) || strings.TrimSpace(tokens[idx]) != val {
				match = false
				break
			}
		}
		if !match {
			result = append(result, p)
		}
	}

	result = append(result, newLines...)
	ma.policies = result
	return nil
}

// LoadFilteredPolicy 按过滤条件从内存加载策略
func (ma *MemoryAdapter) LoadFilteredPolicy(filter interface{}) ([]string, error) {
	ma.filtered = true
	policies, err := ma.LoadPolicy()
	if err != nil {
		return nil, err
	}

	filterValues, ok := filter.([]string)
	if !ok {
		return policies, nil
	}

	var result []string
	for _, p := range policies {
		tokens := strings.Split(p, ",")
		match := true
		for _, fv := range filterValues {
			found := false
			for _, t := range tokens {
				if strings.TrimSpace(t) == fv {
					found = true
					break
				}
			}
			if !found {
				match = false
				break
			}
		}
		if match {
			result = append(result, p)
		}
	}
	return result, nil
}

// IsFiltered 返回是否已使用过滤加载
func (ma *MemoryAdapter) IsFiltered() bool {
	return ma.filtered
}

// ==================== 序列化工具函数 ====================

// SerializePolicy 将策略数据序列化为字节切片
// 基于 go-toolbox/serializer 实现，支持 JSON/MsgPack 等格式
func SerializePolicy[T any](data T) ([]byte, error) {
	s := serializer.New[T]()
	return s.Encode(data)
}

// DeserializePolicy 从字节切片反序列化策略数据
func DeserializePolicy[T any](data []byte) (T, error) {
	s := serializer.New[T]()
	return s.Decode(data)
}
