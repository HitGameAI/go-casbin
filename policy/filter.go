/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\filter.go
 * @Description: 策略过滤器（适配器共享）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import "strings"

// Filter 策略过滤器（所有适配器共用）
type Filter struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// NewFilter 创建过滤器
func NewFilter() *Filter {
	return &Filter{}
}

// 链式设置方法
func (f *Filter) WithPType(v string) *Filter { f.PType = v; return f }
func (f *Filter) WithV0(v string) *Filter    { f.V0 = v; return f }
func (f *Filter) WithV1(v string) *Filter    { f.V1 = v; return f }
func (f *Filter) WithV2(v string) *Filter    { f.V2 = v; return f }
func (f *Filter) WithV3(v string) *Filter    { f.V3 = v; return f }
func (f *Filter) WithV4(v string) *Filter    { f.V4 = v; return f }
func (f *Filter) WithV5(v string) *Filter    { f.V5 = v; return f }

// Values 返回 V0-V5 字段值列表
func (f *Filter) Values() []string {
	return []string{f.V0, f.V1, f.V2, f.V3, f.V4, f.V5}
}

// AllValues 返回所有字段值列表（包含 PType）
func (f *Filter) AllValues() []string {
	return []string{f.PType, f.V0, f.V1, f.V2, f.V3, f.V4, f.V5}
}

// NonEmptyFields 返回非空字段的 map（字段名 -> 值）
func (f *Filter) NonEmptyFields() map[string]string {
	result := make(map[string]string)
	if f.PType != "" {
		result[FieldPType] = f.PType
	}
	for i, val := range f.Values() {
		if val != "" {
			result[PolicyFields[i]] = val
		}
	}
	return result
}

// IsEmpty 检查过滤器是否为空
func (f *Filter) IsEmpty() bool {
	return f.PType == "" && f.V0 == "" && f.V1 == "" && f.V2 == "" && f.V3 == "" && f.V4 == "" && f.V5 == ""
}

// FromSlice 从字符串切片创建过滤器
func (f *Filter) FromSlice(values []string) *Filter {
	if len(values) > 0 {
		f.PType = values[0]
	}
	if len(values) > 1 {
		f.V0 = values[1]
	}
	if len(values) > 2 {
		f.V1 = values[2]
	}
	if len(values) > 3 {
		f.V2 = values[3]
	}
	if len(values) > 4 {
		f.V3 = values[4]
	}
	if len(values) > 5 {
		f.V4 = values[5]
	}
	if len(values) > 6 {
		f.V5 = values[6]
	}
	return f
}

// FilterFromSlice 从字符串切片创建过滤器
func FilterFromSlice(values []string) *Filter {
	return NewFilter().FromSlice(values)
}

// Match 检查策略行是否匹配过滤器
func (f *Filter) Match(line string) bool {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	filterValues := f.AllValues()
	for i, filterVal := range filterValues {
		if filterVal == "" {
			continue
		}
		if i >= len(parts) || parts[i] != filterVal {
			return false
		}
	}
	return true
}

// MatchByIndex 根据字段索引检查策略行是否匹配
func MatchByIndex(line string, fieldIndex int, fieldValues ...string) bool {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	for i, val := range fieldValues {
		idx := fieldIndex + i
		if idx >= len(parts) || parts[idx] != val {
			return false
		}
	}
	return true
}

// FilterPolicies 使用过滤器过滤策略列表
func FilterPolicies(policies []string, filter *Filter) []string {
	if filter == nil || filter.IsEmpty() {
		return policies
	}

	result := make([]string, 0)
	for _, p := range policies {
		if filter.Match(p) {
			result = append(result, p)
		}
	}
	return result
}

// FilterPoliciesByIndex 根据字段索引过滤策略列表
func FilterPoliciesByIndex(policies []string, fieldIndex int, fieldValues ...string) []string {
	if len(fieldValues) == 0 {
		return policies
	}

	result := make([]string, 0)
	for _, p := range policies {
		if MatchByIndex(p, fieldIndex, fieldValues...) {
			result = append(result, p)
		}
	}
	return result
}

// ExtractPType 从策略行提取 PType
func ExtractPType(line string) string {
	parts := strings.SplitN(line, ",", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}
