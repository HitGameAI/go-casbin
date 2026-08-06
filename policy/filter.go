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
// 用于按策略类型和字段值过滤策略，支持链式调用构建过滤条件
// 字段映射：PType=策略类型, V0=主体, V1=资源/角色, V2=操作, V3=效果, V4/V5=扩展
type Filter struct {
	PType string // 策略类型（p/g/p2/g2 等）
	V0    string // 第一个字段值（通常为主体 Subject）
	V1    string // 第二个字段值（通常为资源 Object 或角色 Role）
	V2    string // 第三个字段值（通常为操作 Action）
	V3    string // 第四个字段值（通常为效果 Effect 或域 Domain）
	V4    string // 第五个字段值（扩展字段）
	V5    string // 第六个字段值（扩展字段）
}

// NewFilter 创建过滤器
func NewFilter() *Filter {
	return &Filter{}
}

// 链式设置方法，用于流畅地构建过滤条件
// 示例：NewFilter().WithPType("p").WithV0("alice").WithV1("data1")
func (f *Filter) WithPType(v string) *Filter { f.PType = v; return f } // 设置策略类型
func (f *Filter) WithV0(v string) *Filter    { f.V0 = v; return f }    // 设置主体字段
func (f *Filter) WithV1(v string) *Filter    { f.V1 = v; return f }    // 设置资源/角色字段
func (f *Filter) WithV2(v string) *Filter    { f.V2 = v; return f }    // 设置操作字段
func (f *Filter) WithV3(v string) *Filter    { f.V3 = v; return f }    // 设置效果/域字段
func (f *Filter) WithV4(v string) *Filter    { f.V4 = v; return f }    // 设置扩展字段
func (f *Filter) WithV5(v string) *Filter    { f.V5 = v; return f }    // 设置扩展字段

// Values 返回 V0-V5 字段值列表（不含 PType）
func (f *Filter) Values() []string {
	return []string{f.V0, f.V1, f.V2, f.V3, f.V4, f.V5}
}

// AllValues 返回所有字段值列表（包含 PType）
func (f *Filter) AllValues() []string {
	return []string{f.PType, f.V0, f.V1, f.V2, f.V3, f.V4, f.V5}
}

// NonEmptyFields 返回非空字段的 map（字段名 -> 值）
// 用于构建 SQL WHERE 条件或 Redis 查询条件
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

// IsEmpty 检查过滤器是否为空（所有字段都为空字符串）
func (f *Filter) IsEmpty() bool {
	return f.PType == "" && f.V0 == "" && f.V1 == "" && f.V2 == "" && f.V3 == "" && f.V4 == "" && f.V5 == ""
}

// FromSlice 从字符串切片创建过滤器
// 切片顺序：[PType, V0, V1, V2, V3, V4, V5]
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

// FilterFromSlice 从字符串切片创建过滤器（工厂函数）
func FilterFromSlice(values []string) *Filter {
	return NewFilter().FromSlice(values)
}

// Match 检查策略行是否匹配过滤器
// 将策略行按逗号分割后，逐字段与过滤器的非空字段比较
// 空字段视为通配，不参与匹配
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
// fieldIndex 为起始字段位置，fieldValues 为从该位置开始的连续字段值
// 常用于按主体/资源等特定字段过滤
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
// 如果过滤器为空或所有字段都为空，返回原始列表
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
// 从 fieldIndex 位置开始，逐个比较 fieldValues
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

// InferPType 从策略行列表中推断单一 ptype。
// 如果列表为空、包含空 ptype，或包含多个不同 ptype，则返回空字符串。
func InferPType(lines []string) string {
	var ptype string
	for _, line := range lines {
		linePType := ExtractPType(line)
		if linePType == "" {
			return ""
		}
		if ptype == "" {
			ptype = linePType
			continue
		}
		if ptype != linePType {
			return ""
		}
	}
	return ptype
}

// FilterPoliciesByPType 只保留指定 ptype 的策略行。
func FilterPoliciesByPType(lines []string, ptype string) []string {
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if ExtractPType(line) == ptype {
			result = append(result, line)
		}
	}
	return result
}

// MatchPolicyValuesByIndex 按策略值字段匹配，不包含 ptype。
// fieldIndex=0 表示 V0，而不是 PType；用于 adapter 的 filtered update/remove 语义。
func MatchPolicyValuesByIndex(line string, fieldIndex int, fieldValues ...string) bool {
	if len(fieldValues) == 0 {
		return true
	}
	parts := strings.Split(line, ",")
	values := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		values = append(values, strings.TrimSpace(parts[i]))
	}
	for i, val := range fieldValues {
		idx := fieldIndex + i
		if idx >= len(values) || values[idx] != val {
			return false
		}
	}
	return true
}

// FilterPoliciesByValueIndex 按策略值字段过滤，可选 ptype 限定。
// fieldIndex=0 表示 V0；ptype 为空时不过滤策略类型。
func FilterPoliciesByValueIndex(lines []string, ptype string, fieldIndex int, fieldValues ...string) []string {
	if len(fieldValues) == 0 && ptype == "" {
		return append([]string(nil), lines...)
	}

	result := make([]string, 0)
	for _, line := range lines {
		if ptype != "" && ExtractPType(line) != ptype {
			continue
		}
		if MatchPolicyValuesByIndex(line, fieldIndex, fieldValues...) {
			result = append(result, line)
		}
	}
	return result
}

// ExtractPType 从策略行提取 PType（策略类型）
// 策略行格式为 "p, alice, data1, read"，提取第一个逗号前的部分
func ExtractPType(line string) string {
	parts := strings.SplitN(line, ",", 2)
	return strings.TrimSpace(parts[0])
}
