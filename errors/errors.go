/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\errors\errors.go
 * @Description: 统一错误定义 - 基于 go-toolbox/errorx 的类型化错误体系
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package errors

import (
	"github.com/kamalyes/go-toolbox/pkg/errorx"
)

// ==================== 模型错误类型（2000-2004） ====================

const (
	ErrTypeModelInvalid          errorx.ErrorType = 2000 + iota // 模型无效
	ErrTypeModelLoadFailed                                      // 模型加载失败
	ErrTypeModelParseFailed                                     // 模型解析失败
	ErrTypeModelValidationFailed                                // 模型验证失败
	ErrTypeModelSectionMissing                                  // 模型段缺失
)

// ==================== 策略错误类型（2100-2120） ====================

const (
	ErrTypePolicyNotFound          errorx.ErrorType = 2100 + iota // 策略未找到
	ErrTypePolicyAlreadyExists                                    // 策略已存在
	ErrTypePolicyEffectDenied                                     // 策略效果拒绝
	ErrTypePolicyAdapterFailed                                    // 策略适配器错误
	ErrTypePolicyCacheFailed                                      // 策略缓存错误
	ErrTypePolicyWatchFailed                                      // 策略监控错误
	ErrTypePolicyLoadFailed                                       // 策略加载失败
	ErrTypePolicySaveFailed                                       // 策略保存失败
	ErrTypePolicyAddFailed                                        // 策略添加失败
	ErrTypePolicyRemoveFailed                                     // 策略删除失败
	ErrTypePolicyUpdateFailed                                     // 策略更新失败
	ErrTypePolicyClearFailed                                      // 策略清空失败
	ErrTypePolicyParseFailed                                      // 策略解析失败
	ErrTypePolicyFilterFailed                                     // 策略过滤失败
	ErrTypePolicyCountMismatch                                    // 策略数量不匹配
	ErrTypePolicyBatchAddFailed                                   // 批量添加策略失败
	ErrTypePolicyBatchRemoveFailed                                // 批量删除策略失败
	ErrTypePolicyBatchUpdateFailed                                // 批量更新策略失败
	ErrTypePolicyAutoMigrateFailed                                // 自动迁移策略表失败
	ErrTypePolicyGetByTypeFailed                                  // 按类型获取策略失败
)

// ==================== 角色错误类型（2200-2203） ====================

const (
	ErrTypeRoleNotFound        errorx.ErrorType = 2200 + iota // 角色未找到
	ErrTypeRoleAlreadyExists                                  // 角色已存在
	ErrTypeRoleCycleDetected                                  // 角色循环检测
	ErrTypeRoleHierarchyFailed                                // 角色层级错误
)

// ==================== 执行器错误类型（2300-2304） ====================

const (
	ErrTypeEnforcerNotReady       errorx.ErrorType = 2300 + iota // 执行器未就绪
	ErrTypeEnforcerDisabled                                      // 执行器已禁用
	ErrTypeEnforcerMatcherFailed                                 // 匹配器执行失败
	ErrTypeEnforcerBreakerOpen                                   // 熔断器已开启
	ErrTypeEnforcerRetryExhausted                                // 重试次数耗尽
)

// ==================== 配置错误类型（2400-2402） ====================

const (
	ErrTypeConfigLoadFailed  errorx.ErrorType = 2400 + iota // 配置加载失败
	ErrTypeConfigWatchFailed                                // 配置监控错误
	ErrTypeConfigInvalid                                    // 配置无效
)

// ==================== 监控错误类型（2500） ====================

const (
	ErrTypeMonitorFailed errorx.ErrorType = 2500 + iota // 监控错误
)

// init 注册所有错误类型及其默认消息模板
// 错误消息使用英文，格式字符串中的 %s 会被具体细节替换
func init() {
	// 模型相关错误
	errorx.RegisterError(ErrTypeModelInvalid, "invalid model: %s")
	errorx.RegisterError(ErrTypeModelLoadFailed, "failed to load model: %s")
	errorx.RegisterError(ErrTypeModelParseFailed, "failed to parse model: %s")
	errorx.RegisterError(ErrTypeModelValidationFailed, "model validation failed: %s")
	errorx.RegisterError(ErrTypeModelSectionMissing, "model section missing: %s")

	// 策略相关错误
	errorx.RegisterError(ErrTypePolicyNotFound, "policy not found: %s")
	errorx.RegisterError(ErrTypePolicyAlreadyExists, "policy already exists: %s")
	errorx.RegisterError(ErrTypePolicyEffectDenied, "policy effect denied: %s")
	errorx.RegisterError(ErrTypePolicyAdapterFailed, "policy adapter error: %s")
	errorx.RegisterError(ErrTypePolicyCacheFailed, "policy cache error: %s")
	errorx.RegisterError(ErrTypePolicyWatchFailed, "policy watch error: %s")
	errorx.RegisterError(ErrTypePolicyLoadFailed, "failed to load policy: %s")
	errorx.RegisterError(ErrTypePolicySaveFailed, "failed to save policy: %s")
	errorx.RegisterError(ErrTypePolicyAddFailed, "failed to add policy: %s")
	errorx.RegisterError(ErrTypePolicyRemoveFailed, "failed to remove policy: %s")
	errorx.RegisterError(ErrTypePolicyUpdateFailed, "failed to update policy: %s")
	errorx.RegisterError(ErrTypePolicyClearFailed, "failed to clear policy: %s")
	errorx.RegisterError(ErrTypePolicyParseFailed, "failed to parse policy: %s")
	errorx.RegisterError(ErrTypePolicyFilterFailed, "failed to filter policy: %s")
	errorx.RegisterError(ErrTypePolicyCountMismatch, "policy count mismatch: %s")
	errorx.RegisterError(ErrTypePolicyBatchAddFailed, "failed to batch add policy: %s")
	errorx.RegisterError(ErrTypePolicyBatchRemoveFailed, "failed to batch remove policy: %s")
	errorx.RegisterError(ErrTypePolicyBatchUpdateFailed, "failed to batch update policy: %s")
	errorx.RegisterError(ErrTypePolicyAutoMigrateFailed, "failed to auto migrate policy table: %s")
	errorx.RegisterError(ErrTypePolicyGetByTypeFailed, "failed to get policy by type: %s")

	// 角色相关错误
	errorx.RegisterError(ErrTypeRoleNotFound, "role not found: %s")
	errorx.RegisterError(ErrTypeRoleAlreadyExists, "role already exists: %s")
	errorx.RegisterError(ErrTypeRoleCycleDetected, "role cycle detected: %s -> %s")
	errorx.RegisterError(ErrTypeRoleHierarchyFailed, "role hierarchy error: %s")

	// 执行器相关错误
	errorx.RegisterError(ErrTypeEnforcerNotReady, "enforcer is not ready: %s")
	errorx.RegisterError(ErrTypeEnforcerDisabled, "enforcer is disabled: %s")
	errorx.RegisterError(ErrTypeEnforcerMatcherFailed, "matcher execution failed: %s")
	errorx.RegisterError(ErrTypeEnforcerBreakerOpen, "circuit breaker is open: %s")
	errorx.RegisterError(ErrTypeEnforcerRetryExhausted, "retry attempts exhausted: %s")

	// 配置相关错误
	errorx.RegisterError(ErrTypeConfigLoadFailed, "failed to load config: %s")
	errorx.RegisterError(ErrTypeConfigWatchFailed, "config watch error: %s")
	errorx.RegisterError(ErrTypeConfigInvalid, "invalid configuration: %s")

	// 监控相关错误
	errorx.RegisterError(ErrTypeMonitorFailed, "monitor error: %s")
}

// ==================== 模型错误构造函数 ====================

// NewModelInvalidError 创建模型无效错误
func NewModelInvalidError(detail string) error {
	return errorx.NewError(ErrTypeModelInvalid, detail)
}

// NewModelLoadFailedError 创建模型加载失败错误
func NewModelLoadFailedError(detail string) error {
	return errorx.NewError(ErrTypeModelLoadFailed, detail)
}

// NewModelParseFailedError 创建模型解析失败错误
func NewModelParseFailedError(detail string) error {
	return errorx.NewError(ErrTypeModelParseFailed, detail)
}

// NewModelValidationFailedError 创建模型验证失败错误
func NewModelValidationFailedError(detail string) error {
	return errorx.NewError(ErrTypeModelValidationFailed, detail)
}

// NewModelSectionMissingError 创建模型段缺失错误
func NewModelSectionMissingError(section string) error {
	return errorx.NewError(ErrTypeModelSectionMissing, section)
}

// ==================== 策略错误构造函数 ====================

// NewPolicyNotFoundError 创建策略未找到错误
func NewPolicyNotFoundError(detail string) error {
	return errorx.NewError(ErrTypePolicyNotFound, detail)
}

// NewPolicyAlreadyExistsError 创建策略已存在错误
func NewPolicyAlreadyExistsError(detail string) error {
	return errorx.NewError(ErrTypePolicyAlreadyExists, detail)
}

// NewPolicyEffectDeniedError 创建策略效果拒绝错误
func NewPolicyEffectDeniedError(detail string) error {
	return errorx.NewError(ErrTypePolicyEffectDenied, detail)
}

// NewPolicyAdapterFailedError 创建策略适配器错误
func NewPolicyAdapterFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyAdapterFailed, detail)
}

// NewPolicyCacheFailedError 创建策略缓存错误
func NewPolicyCacheFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyCacheFailed, detail)
}

// NewPolicyWatchFailedError 创建策略监控错误
func NewPolicyWatchFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyWatchFailed, detail)
}

// NewPolicyLoadFailedError 创建策略加载失败错误
func NewPolicyLoadFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyLoadFailed, detail)
}

// NewPolicySaveFailedError 创建策略保存失败错误
func NewPolicySaveFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicySaveFailed, detail)
}

// NewPolicyAddFailedError 创建策略添加失败错误
func NewPolicyAddFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyAddFailed, detail)
}

// NewPolicyRemoveFailedError 创建策略删除失败错误
func NewPolicyRemoveFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyRemoveFailed, detail)
}

// NewPolicyUpdateFailedError 创建策略更新失败错误
func NewPolicyUpdateFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyUpdateFailed, detail)
}

// NewPolicyClearFailedError 创建策略清空失败错误
func NewPolicyClearFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyClearFailed, detail)
}

// NewPolicyParseFailedError 创建策略解析失败错误
func NewPolicyParseFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyParseFailed, detail)
}

// NewPolicyFilterFailedError 创建策略过滤失败错误
func NewPolicyFilterFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyFilterFailed, detail)
}

// NewPolicyCountMismatchError 创建策略数量不匹配错误
func NewPolicyCountMismatchError(detail string) error {
	return errorx.NewError(ErrTypePolicyCountMismatch, detail)
}

// NewPolicyBatchAddFailedError 创建批量添加策略失败错误
func NewPolicyBatchAddFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyBatchAddFailed, detail)
}

// NewPolicyBatchRemoveFailedError 创建批量删除策略失败错误
func NewPolicyBatchRemoveFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyBatchRemoveFailed, detail)
}

// NewPolicyBatchUpdateFailedError 创建批量更新策略失败错误
func NewPolicyBatchUpdateFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyBatchUpdateFailed, detail)
}

// NewPolicyAutoMigrateFailedError 创建自动迁移策略表失败错误
func NewPolicyAutoMigrateFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyAutoMigrateFailed, detail)
}

// NewPolicyGetByTypeFailedError 创建按类型获取策略失败错误
func NewPolicyGetByTypeFailedError(detail string) error {
	return errorx.NewError(ErrTypePolicyGetByTypeFailed, detail)
}

// ==================== 角色错误构造函数 ====================

// NewRoleNotFoundError 创建角色未找到错误
func NewRoleNotFoundError(detail string) error {
	return errorx.NewError(ErrTypeRoleNotFound, detail)
}

// NewRoleAlreadyExistsError 创建角色已存在错误
func NewRoleAlreadyExistsError(detail string) error {
	return errorx.NewError(ErrTypeRoleAlreadyExists, detail)
}

// NewRoleCycleDetectedError 创建角色循环检测错误
func NewRoleCycleDetectedError(from, to string) error {
	return errorx.NewError(ErrTypeRoleCycleDetected, from, to)
}

// NewRoleHierarchyFailedError 创建角色层级错误
func NewRoleHierarchyFailedError(detail string) error {
	return errorx.NewError(ErrTypeRoleHierarchyFailed, detail)
}

// ==================== 执行器错误构造函数 ====================

// NewEnforcerNotReadyError 创建执行器未就绪错误
func NewEnforcerNotReadyError(detail string) error {
	return errorx.NewError(ErrTypeEnforcerNotReady, detail)
}

// NewEnforcerDisabledError 创建执行器已禁用错误
func NewEnforcerDisabledError(detail string) error {
	return errorx.NewError(ErrTypeEnforcerDisabled, detail)
}

// NewEnforcerMatcherFailedError 创建匹配器执行失败错误
func NewEnforcerMatcherFailedError(detail string) error {
	return errorx.NewError(ErrTypeEnforcerMatcherFailed, detail)
}

// NewEnforcerBreakerOpenError 创建熔断器已开启错误
func NewEnforcerBreakerOpenError(detail string) error {
	return errorx.NewError(ErrTypeEnforcerBreakerOpen, detail)
}

// NewEnforcerRetryExhaustedError 创建重试次数耗尽错误
func NewEnforcerRetryExhaustedError(detail string) error {
	return errorx.NewError(ErrTypeEnforcerRetryExhausted, detail)
}

// ==================== 配置错误构造函数 ====================

// NewConfigLoadFailedError 创建配置加载失败错误
func NewConfigLoadFailedError(detail string) error {
	return errorx.NewError(ErrTypeConfigLoadFailed, detail)
}

// NewConfigWatchFailedError 创建配置监控错误
func NewConfigWatchFailedError(detail string) error {
	return errorx.NewError(ErrTypeConfigWatchFailed, detail)
}

// NewConfigInvalidError 创建配置无效错误
func NewConfigInvalidError(detail string) error {
	return errorx.NewError(ErrTypeConfigInvalid, detail)
}

// ==================== 监控错误构造函数 ====================

// NewMonitorFailedError 创建监控错误
func NewMonitorFailedError(detail string) error {
	return errorx.NewError(ErrTypeMonitorFailed, detail)
}

// ==================== 通用错误工具函数 ====================

// WrapError 包装原始错误，添加上下文消息
func WrapError(message string, err error) error {
	return errorx.WrapError(message, err)
}
