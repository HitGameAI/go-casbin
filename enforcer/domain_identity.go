/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-08-01 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-08-01 00:15:16
 * @FilePath: \go-casbin\enforcer\domain_identity.go
 * @Description: 租户域名身份绑定（正向校验 + 反向查询共用同一条 p2 策略）
 *
 * 每个 host 绑定只存一条 p2 策略，同时服务正向校验和反向查询：
 *   p2 = r.sub != "", <tenantID>, "domain::<host>", HOST
 *
 * 1. 正向校验 EnforceTenantHostBinding：通过 Enforce 匹配，r.act == HOST
 * 2. 反向查询 ResolveTenantByHost：通过 GetFilteredNamedPolicy 按 act=HOST 过滤，读取 dom 字段获取 tenantID
 *
 * 联动保证：SyncTenantHostBindings 对每个 host 添加/删除策略，
 * 确保登录反查（ResolveTenantByHost）和授权正向校验（EnforceTenantHostBinding）数据一致
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"net"
	"strings"

	"github.com/kamalyes/go-casbin/policy"
)

// TenantHostBinding 租户域名绑定关系
type TenantHostBinding struct {
	TenantID string
	Host     string
}

const (
	// domainIdentityAction 域名身份绑定动作（正向校验 + 反向查询共用）
	domainIdentityAction = "HOST"

	// domainIdentitySubRule 主体规则（sub 非空即可，不限定具体用户）
	domainIdentitySubRule = `r.sub != ""`

	// domainIdentityResourcePrefix 资源前缀
	domainIdentityResourcePrefix = "domain::"
)

// NormalizeDomainHost 归一化请求域名标识
// 处理 X-Forwarded-Host 多值取首、host:port 剥离端口、IPv6 括号、trailing dot、小写
func NormalizeDomainHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if forwardedHost := strings.Split(host, ",")[0]; forwardedHost != "" {
		host = strings.TrimSpace(forwardedHost)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// SyncTenantHostBindings 批量同步租户域名绑定
// 对 addHosts 中每个 host 添加策略；removeHosts 删除策略
// tenantID 为空时跳过（OPS 域无域名限制）
func (e *Enforcer) SyncTenantHostBindings(tenantID string, addHosts, removeHosts []string) error {
	if tenantID == "" {
		return nil
	}
	for _, host := range addHosts {
		if err := e.addTenantHostBinding(tenantID, host); err != nil {
			return err
		}
	}
	for _, host := range removeHosts {
		if err := e.removeTenantHostBinding(tenantID, host); err != nil {
			return err
		}
	}
	return nil
}

// EnforceTenantHostBinding 校验 tenantID 是否绑定了 host（正向校验）
// 通过 p2 正向校验策略匹配，仅用于已认证场景（需 userID）
func (e *Enforcer) EnforceTenantHostBinding(tenantID, userID, host string) (bool, error) {
	host = NormalizeDomainHost(host)
	if tenantID == "" || userID == "" || host == "" {
		return false, nil
	}
	return e.Enforce(userID, tenantID, domainIdentityResourcePrefix+host, domainIdentityAction)
}

// ResolveTenantByHost 根据 host 反查绑定的 tenantID
// 供登录/忘记密码等未认证场景按 host 解析租户；空串表示未绑定
func (e *Enforcer) ResolveTenantByHost(host string) (string, error) {
	host = NormalizeDomainHost(host)
	if host == "" {
		return "", nil
	}
	resource := domainIdentityResourcePrefix + host
	for _, p := range e.GetFilteredNamedPolicy(policy.PTypePolicy2, 2, resource, domainIdentityAction) {
		if len(p) > 1 && p[1] != "" {
			return p[1], nil
		}
	}
	return "", nil
}

// ListTenantHostBindings 列出租户域名绑定
// tenantID 为空时列出所有租户的绑定，非空时仅列出指定租户的绑定
func (e *Enforcer) ListTenantHostBindings(tenantID string) []TenantHostBinding {
	bindings := make([]TenantHostBinding, 0)
	for _, p := range e.GetFilteredNamedPolicy(policy.PTypePolicy2, 3, domainIdentityAction) {
		// p = [v0=sub_rule, v1=tenantID, v2=domain::host, v3=action]
		if len(p) < 3 || p[1] == "" {
			continue
		}
		if tenantID != "" && p[1] != tenantID {
			continue
		}
		host := strings.TrimPrefix(p[2], domainIdentityResourcePrefix)
		if host == "" {
			continue
		}
		bindings = append(bindings, TenantHostBinding{TenantID: p[1], Host: host})
	}
	return bindings
}

// addTenantHostBinding 添加租户 host 绑定（幂等）
func (e *Enforcer) addTenantHostBinding(tenantID, host string) error {
	host = NormalizeDomainHost(host)
	if host == "" || tenantID == "" {
		return nil
	}
	resource := domainIdentityResourcePrefix + host
	if !e.HasNamedPolicy(policy.PTypePolicy2, domainIdentitySubRule, tenantID, resource, domainIdentityAction) {
		return e.AddNamedPolicy(policy.PTypePolicy2, domainIdentitySubRule, tenantID, resource, domainIdentityAction)
	}
	return nil
}

// removeTenantHostBinding 删除租户 host 绑定
func (e *Enforcer) removeTenantHostBinding(tenantID, host string) error {
	host = NormalizeDomainHost(host)
	if host == "" || tenantID == "" {
		return nil
	}
	resource := domainIdentityResourcePrefix + host
	return e.RemoveNamedPolicy(policy.PTypePolicy2, domainIdentitySubRule, tenantID, resource, domainIdentityAction)
}
