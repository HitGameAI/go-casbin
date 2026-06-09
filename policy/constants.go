/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\constants.go
 * @Description: 策略相关常量定义
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

// 策略字段名常量 (对应数据库列名)
// Casbin 策略最多支持 6 个参数字段（V0-V5），加上策略类型 PType 共 7 个字段
const (
	FieldPType = "p_type" // 策略类型字段（p=权限策略, g=角色分组）
	FieldV0    = "v0"     // 第1个参数（通常为 sub 主体）
	FieldV1    = "v1"     // 第2个参数（通常为 obj 客体）
	FieldV2    = "v2"     // 第3个参数（通常为 act 操作）
	FieldV3    = "v3"     // 第4个参数（通常为 eft 效果或 dom 域）
	FieldV4    = "v4"     // 第5个参数
	FieldV5    = "v5"     // 第6个参数
)

// PolicyFields 策略参数字段列表（V0-V5，不含 PType）
// 按顺序排列，用于按索引访问策略参数
var PolicyFields = []string{FieldV0, FieldV1, FieldV2, FieldV3, FieldV4, FieldV5}

// AllFields 所有字段列表（PType + V0-V5）
// 用于数据库查询时指定所有列
var AllFields = []string{FieldPType, FieldV0, FieldV1, FieldV2, FieldV3, FieldV4, FieldV5}

// MaxPolicyFields 策略最大参数字段数（V0-V5 共 6 个）
const MaxPolicyFields = 6

// 策略类型常量
// Casbin 使用 p 和 g 两种核心策略类型，支持多定义（p2、g2 等）
const (
	PTypePolicy    = "p"  // 权限策略：定义主体对资源的操作权限
	PTypePolicy2   = "p2" // 权限策略2：用于复合权限场景
	PTypeGrouping  = "g"  // 角色分组：定义用户与角色的继承关系
	PTypeGrouping2 = "g2" // 角色分组2：用于带域的角色继承（多租户）
)

// 函数前缀
const (
	EvalFunc = "eval(" // 评估函数前缀
	GFunc    = "g("    // 角色继承组函数前缀
)

// 语义化字段索引（用于 Domain RBAC）
// 定义策略参数在数组中的标准位置，便于按语义访问
const (
	IdxSub   = 0 // Subject (用户/角色) - 策略主体
	IdxDom   = 1 // Domain (域/租户) - 多租户场景下的隔离域
	IdxObj   = 2 // Object (资源) - 被访问的客体
	IdxAct   = 3 // Action (操作) - 对资源的访问方式
	IdxEft   = 4 // Effect (允许/拒绝) - 策略效果
	IdxExtra = 5 // Extra (扩展字段) - 预留的扩展参数
)

// GetFieldByIndex 根据索引获取字段名
// 索引 0 对应 V0，索引 1 对应 V1，以此类推
// 超出范围返回空字符串
func GetFieldByIndex(index int) string {
	if index < 0 || index >= len(PolicyFields) {
		return ""
	}
	return PolicyFields[index]
}

// GetFieldsFromIndex 从指定索引开始获取指定数量的字段列表
// 用于构建数据库查询时的字段选择
func GetFieldsFromIndex(startIndex int, count int) []string {
	if startIndex < 0 || startIndex >= len(PolicyFields) {
		return nil
	}

	end := startIndex + count
	if end > len(PolicyFields) {
		end = len(PolicyFields)
	}

	return PolicyFields[startIndex:end]
}
