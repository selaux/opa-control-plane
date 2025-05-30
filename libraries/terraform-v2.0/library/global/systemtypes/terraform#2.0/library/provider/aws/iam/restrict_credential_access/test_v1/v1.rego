package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_credential_access.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_credential_access.v1

############
# unit tests

test_restrict_credential_access_for_iam_policy_good {
	in := input_with_iam_policy(default_policy_config, default_policy_config, default_policy_config, default_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 0
}

test_restrict_credential_access_for_iam_policy_bad_user_policy {
	user_policy_config := "{\"Statement\":[{\"Action\":[\"iam:ListAccessKeys\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(default_policy_config, user_policy_config, default_policy_config, default_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 1
}

test_restrict_credential_access_for_iam_policy_bad_user_and_group_policy {
	user_policy_config := "{\"Statement\":[{\"Action\":[\"iam:DeleteAccessKey\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	group_policy_config := "{\"Statement\":[{\"Action\":[\"iam:*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(default_policy_config, user_policy_config, default_policy_config, group_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 2
}

test_restrict_credential_access_for_iam_policy_bad_role_policy {
	role_policy_config := "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(default_policy_config, default_policy_config, role_policy_config, default_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 1
}

test_restrict_credential_access_for_iam_policy_bad_iam_policy {
	policy_config := "{\"Statement\":[{\"Action\":[\"iam:CreateAccessKey\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(policy_config, default_policy_config, default_policy_config, default_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 1
}

test_restrict_credential_access_for_iam_policy_bad_all_actions {
	policy_config := "{\"Statement\":[{\"Action\":[\"iam:UpdateAccessKey\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	role_policy_config := "{\"Statement\":[{\"Action\":\"iam:*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(policy_config, default_policy_config, role_policy_config, default_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 2
}

test_restrict_credential_access_for_iam_policy_bad_all {
	policy_config := "{\"Statement\":[{\"Action\":[\"iam:UpdateAccessKey\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	role_policy_config := "{\"Statement\":[{\"Action\":\"iam:*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	group_policy_config := "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	user_policy_config := "{\"Statement\":[{\"Action\":[\"iam:ListAccessKeys\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"
	in := input_with_iam_policy(policy_config, user_policy_config, role_policy_config, group_policy_config)

	actual := v1.restrict_credential_access_for_iam_policy with input as in

	count(actual) == 4
}

#################
# test input data

default_policy_config := "{\"Statement\":[{\"Action\":[\"ec2:Describe\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"

input_with_iam_policy(policy_config, user_policy_config, role_policy_config, group_policy_config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.15",
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
				"address": "aws_iam_group.my_developers",
				"mode": "managed",
				"type": "aws_iam_group",
				"name": "my_developers",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"name": "developers",
					"path": "/users/",
				},
			},
			{
				"address": "aws_iam_group_policy.my_developer_policy",
				"mode": "managed",
				"type": "aws_iam_group_policy",
				"name": "my_developer_policy",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"group": "developers",
					"name": "my_developer_policy",
					"name_prefix": null,
					"policy": group_policy_config,
				},
			},
			{
				"address": "aws_iam_policy.policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "policy",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"description": "My test policy",
					"name": "test_policy",
					"name_prefix": null,
					"path": "/",
					"policy": policy_config,
				},
			},
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
					"name_prefix": null,
					"path": "/",
					"permissions_boundary": null,
					"tags": null,
				},
			},
			{
				"address": "aws_iam_role_policy.test_policy",
				"mode": "managed",
				"type": "aws_iam_role_policy",
				"name": "test_policy",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"name": "test_policy",
					"name_prefix": null,
					"policy": role_policy_config,
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
				"address": "aws_iam_user_policy.lb_ro",
				"mode": "managed",
				"type": "aws_iam_user_policy",
				"name": "lb_ro",
				"provider_name": "aws",
				"schema_version": 0,
				"values": {
					"name": "test",
					"name_prefix": null,
					"policy": user_policy_config,
					"user": "loadbalancer",
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
						"encrypted_secret": true,
						"id": true,
						"key_fingerprint": true,
						"secret": true,
						"ses_smtp_password": true,
						"ses_smtp_password_v4": true,
						"status": true,
					},
				},
			},
			{
				"address": "aws_iam_group.my_developers",
				"mode": "managed",
				"type": "aws_iam_group",
				"name": "my_developers",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"name": "developers",
						"path": "/users/",
					},
					"after_unknown": {
						"arn": true,
						"id": true,
						"unique_id": true,
					},
				},
			},
			{
				"address": "aws_iam_group_policy.my_developer_policy",
				"mode": "managed",
				"type": "aws_iam_group_policy",
				"name": "my_developer_policy",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"group": "developers",
						"name": "my_developer_policy",
						"name_prefix": null,
						"policy": group_policy_config,
					},
					"after_unknown": {"id": true},
				},
			},
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
						"description": "My test policy",
						"name": "test_policy",
						"name_prefix": null,
						"path": "/",
						"policy": policy_config,
					},
					"after_unknown": {
						"arn": true,
						"id": true,
					},
				},
			},
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
						"description": null,
						"force_detach_policies": false,
						"max_session_duration": 3600,
						"name": "test_role",
						"name_prefix": null,
						"path": "/",
						"permissions_boundary": null,
						"tags": null,
					},
					"after_unknown": {
						"arn": true,
						"create_date": true,
						"id": true,
						"unique_id": true,
					},
				},
			},
			{
				"address": "aws_iam_role_policy.test_policy",
				"mode": "managed",
				"type": "aws_iam_role_policy",
				"name": "test_policy",
				"provider_name": "aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"name": "test_policy",
						"name_prefix": null,
						"policy": role_policy_config,
					},
					"after_unknown": {
						"id": true,
						"role": true,
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
						"policy": user_policy_config,
						"user": "loadbalancer",
					},
					"after_unknown": {"id": true},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"constant_value": "us-east-1"},
				},
			}},
			"root_module": {"resources": [
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
					"address": "aws_iam_group.my_developers",
					"mode": "managed",
					"type": "aws_iam_group",
					"name": "my_developers",
					"provider_config_key": "aws",
					"expressions": {
						"name": {"constant_value": "developers"},
						"path": {"constant_value": "/users/"},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_iam_group_policy.my_developer_policy",
					"mode": "managed",
					"type": "aws_iam_group_policy",
					"name": "my_developer_policy",
					"provider_config_key": "aws",
					"expressions": {
						"group": {"references": ["aws_iam_group.my_developers"]},
						"name": {"constant_value": "my_developer_policy"},
						"policy": {},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_iam_policy.policy",
					"mode": "managed",
					"type": "aws_iam_policy",
					"name": "policy",
					"provider_config_key": "aws",
					"expressions": {
						"description": {"constant_value": "My test policy"},
						"name": {"constant_value": "test_policy"},
						"path": {"constant_value": "/"},
						"policy": {},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_iam_role.test_role",
					"mode": "managed",
					"type": "aws_iam_role",
					"name": "test_role",
					"provider_config_key": "aws",
					"expressions": {
						"assume_role_policy": {},
						"name": {"constant_value": "test_role"},
					},
					"schema_version": 0,
				},
				{
					"address": "aws_iam_role_policy.test_policy",
					"mode": "managed",
					"type": "aws_iam_role_policy",
					"name": "test_policy",
					"provider_config_key": "aws",
					"expressions": {
						"name": {"constant_value": "test_policy"},
						"policy": {},
						"role": {"references": ["aws_iam_role.test_role"]},
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
			]},
		},
	}
}
