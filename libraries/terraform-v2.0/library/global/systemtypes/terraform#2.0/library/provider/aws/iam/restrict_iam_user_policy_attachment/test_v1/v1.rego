package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_iam_user_policy_attachment.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_iam_user_policy_attachment.v1

test_restrict_iam_user_policy_attachment_bad {
	in := input_iam_user_policy_and_attachment
	actual := v1.restrict_attaching_iam_user_policy with input as in
	count(actual) == 2
}

test_restrict_iam_user_policy_attachment_bad_2 {
	in := input_iam_user_policy_attachment
	actual := v1.restrict_attaching_iam_user_policy with input as in
	count(actual) == 1
}

test_restrict_iam_user_only_good {
	in := input_iam_user_only
	actual := v1.restrict_attaching_iam_user_policy with input as in
	count(actual) == 0
}

input_iam_user_policy_and_attachment = {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "A test policy",
				"name": "test-policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "loadbalancer",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "test-user",
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user_policy.lb_ro",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "lb_ro",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "test",
				"name_prefix": null,
				"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
				"user": "loadbalancer",
			},
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"user": "test-user"},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "A test policy",
					"name": "test-policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"policy_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "loadbalancer",
					"path": "/system/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "test-user",
					"path": "/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user_policy.lb_ro",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "lb_ro",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "test",
					"name_prefix": null,
					"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
					"user": "loadbalancer",
				},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"user": "test-user"},
				"after_unknown": {
					"id": true,
					"policy_arn": true,
				},
			},
		},
	],
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_config_key": "aws",
			"expressions": {
				"description": {"constant_value": "A test policy"},
				"name": {"constant_value": "test-policy"},
				"policy": {},
			},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_config_key": "aws",
			"expressions": {
				"name": {"constant_value": "loadbalancer"},
				"path": {"constant_value": "/system/"},
			},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_config_key": "aws",
			"expressions": {"name": {"constant_value": "test-user"}},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user_policy.lb_ro",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "lb_ro",
			"provider_config_key": "aws",
			"expressions": {
				"name": {"constant_value": "test"},
				"policy": {},
				"user": {"references": ["aws_iam_user.lb"]},
			},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_config_key": "aws",
			"expressions": {
				"policy_arn": {"references": ["aws_iam_policy.policy"]},
				"user": {"references": ["aws_iam_user.user"]},
			},
			"schema_version": 0,
		},
	]}},
}

input_iam_user_policy_attachment = {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "A test policy",
				"name": "test-policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "test-user",
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"user": "test-user"},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "A test policy",
					"name": "test-policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}",
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"policy_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "test-user",
					"path": "/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"user": "test-user"},
				"after_unknown": {
					"id": true,
					"policy_arn": true,
				},
			},
		},
	],
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "policy",
			"provider_config_key": "aws",
			"expressions": {
				"description": {"constant_value": "A test policy"},
				"name": {"constant_value": "test-policy"},
				"policy": {},
			},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_config_key": "aws",
			"expressions": {"name": {"constant_value": "test-user"}},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user_policy_attachment.test-attach",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "test-attach",
			"provider_config_key": "aws",
			"expressions": {
				"policy_arn": {"references": ["aws_iam_policy.policy"]},
				"user": {"references": ["aws_iam_user.user"]},
			},
			"schema_version": 0,
		},
	]}},
}

input_iam_user_only = {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_access_key.lb",
			"mode": "managed",
			"type": "aws_iam_access_key",
			"name": "lb",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"pgp_key": null,
				"user": "loadbalancer",
			},
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "loadbalancer",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": {"tag-key": "tag-value"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_access_key.lb",
			"mode": "managed",
			"type": "aws_iam_access_key",
			"name": "lb",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"pgp_key": null,
					"user": "loadbalancer",
				},
				"after_unknown": {
					"create_date": true,
					"encrypted_secret": true,
					"id": true,
					"key_fingerprint": true,
					"secret": true,
					"ses_smtp_password_v4": true,
					"status": true,
				},
			},
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "loadbalancer",
					"path": "/system/",
					"permissions_boundary": null,
					"tags": {"tag-key": "tag-value"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"tags": {},
					"unique_id": true,
				},
			},
		},
	],
	"configuration": {"root_module": {"resources": [
		{
			"address": "aws_iam_access_key.lb",
			"mode": "managed",
			"type": "aws_iam_access_key",
			"name": "lb",
			"provider_config_key": "aws",
			"expressions": {"user": {"references": ["aws_iam_user.lb"]}},
			"schema_version": 0,
		},
		{
			"address": "aws_iam_user.lb",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "lb",
			"provider_config_key": "aws",
			"expressions": {
				"name": {"constant_value": "loadbalancer"},
				"path": {"constant_value": "/system/"},
				"tags": {"constant_value": {"tag-key": "tag-value"}},
			},
			"schema_version": 0,
		},
	]}},
}
