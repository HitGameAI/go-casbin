/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\validator.go
 * @Description: 模型验证器（完整性检查）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"fmt"
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	casbinErrors "github.com/kamalyes/go-casbin/errors"
)

var requiredSections = []string{SectionRequestDefinition, SectionPolicyDefinition, SectionPolicyEffect, SectionMatchers}

func ValidateModel(assertions map[string]*Assertion) error {
	var missing []string

	for _, section := range requiredSections {
		found := false
		for key := range assertions {
			if strings.HasPrefix(key, section) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, section)
		}
	}

	if len(missing) > 0 {
		return casbinErrors.NewModelSectionMissingError(strings.Join(missing, ", "))
	}

	if err := validateRequestDefinition(assertions); err != nil {
		return err
	}

	if err := validatePolicyDefinition(assertions); err != nil {
		return err
	}

	if err := validatePolicyEffect(assertions); err != nil {
		return err
	}

	return nil
}

func validateRequestDefinition(assertions map[string]*Assertion) error {
	for key, assertion := range assertions {
		if strings.HasPrefix(key, SectionRequestDefinition) && len(assertion.Tokens) == 0 {
			return errors.NewModelValidationFailedError(
				fmt.Sprintf("request definition %q has no tokens", key),
			)
		}
	}
	return nil
}

func validatePolicyDefinition(assertions map[string]*Assertion) error {
	for key, assertion := range assertions {
		if strings.HasPrefix(key, SectionPolicyDefinition) && len(assertion.Tokens) == 0 {
			return errors.NewModelValidationFailedError(
				fmt.Sprintf("policy definition %q has no tokens", key),
			)
		}
	}
	return nil
}

func validatePolicyEffect(assertions map[string]*Assertion) error {
	for key, assertion := range assertions {
		if strings.HasPrefix(key, SectionPolicyEffect) {
			value := strings.TrimSpace(assertion.Value)
			if value == "" {
				return errors.NewModelValidationFailedError(
					fmt.Sprintf("policy effect %q is empty", key),
				)
			}
		}
	}
	return nil
}
