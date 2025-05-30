package global.systemtypes["terraform:2.0"].library.provider.aws.sagemaker.no_direct_internet_access.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.sagemaker.no_direct_internet_access.v1

test_no_direct_internet_access_good {
	values := {
		"additional_code_repositories": null,
		"default_code_repository": null,
		"direct_internet_access": "Disabled",
		"instance_type": "ml.t2.medium",
		"kms_key_id": null,
		"lifecycle_config_name": null,
		"name": "my-notebook-instance",
		"root_access": "Enabled",
		"subnet_id": null,
		"tags": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"tags_all": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"volume_size": 5,
	}

	in := input_sagemaker_instance(values)
	actual := v1.direct_internet_access_disabled with input as in
	count(actual) == 0
}

test_no_direct_internet_access_bad {
	values := {
		"additional_code_repositories": null,
		"default_code_repository": null,
		"direct_internet_access": "Enabled",
		"instance_type": "ml.t2.medium",
		"kms_key_id": null,
		"lifecycle_config_name": null,
		"name": "my-notebook-instance",
		"root_access": "Enabled",
		"subnet_id": null,
		"tags": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"tags_all": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"volume_size": 5,
	}

	in := input_sagemaker_instance(values)
	actual := v1.direct_internet_access_disabled with input as in
	count(actual) == 1
}

test_no_direct_internet_access_bad_absent {
	values := {
		"additional_code_repositories": null,
		"default_code_repository": null,
		"instance_type": "ml.t2.medium",
		"kms_key_id": null,
		"lifecycle_config_name": null,
		"name": "my-notebook-instance",
		"root_access": "Enabled",
		"subnet_id": null,
		"tags": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"tags_all": {
			"Name": "Sample-Sagemaker-Notebook-Instance",
			"Purpose": "Policy Library Development",
		},
		"volume_size": 5,
	}

	in := input_sagemaker_instance(values)
	actual := v1.direct_internet_access_disabled with input as in
	count(actual) == 1
}

input_sagemaker_instance(values) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.2",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
					"path": "/",
					"permissions_boundary": null,
					"tags": {"Name": "Sample-IAM-Role"},
					"tags_all": {"Name": "Sample-IAM-Role"},
				},
				"sensitive_values": {
					"inline_policy": [],
					"managed_policy_arns": [],
					"tags": {},
					"tags_all": {},
				},
			},
			{
				"address": "aws_sagemaker_notebook_instance.sample_ni",
				"mode": "managed",
				"type": "aws_sagemaker_notebook_instance",
				"name": "sample_ni",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": values,
				"sensitive_values": {
					"security_groups": [],
					"tags": {},
					"tags_all": {},
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
						"description": null,
						"force_detach_policies": false,
						"max_session_duration": 3600,
						"name": "test_role",
						"path": "/",
						"permissions_boundary": null,
						"tags": {"Name": "Sample-IAM-Role"},
						"tags_all": {"Name": "Sample-IAM-Role"},
					},
					"after_unknown": {
						"arn": true,
						"create_date": true,
						"id": true,
						"inline_policy": true,
						"managed_policy_arns": true,
						"name_prefix": true,
						"tags": {},
						"tags_all": {},
						"unique_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"inline_policy": [],
						"managed_policy_arns": [],
						"tags": {},
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_sagemaker_notebook_instance.sample_ni",
				"mode": "managed",
				"type": "aws_sagemaker_notebook_instance",
				"name": "sample_ni",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": values,
					"before_sensitive": false,
					"after_sensitive": {
						"security_groups": [],
						"tags": {},
						"tags_all": {},
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 3.27",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"references": ["var.region"]},
				},
			}},
			"root_module": {
				"resources": [
					{
						"address": "aws_iam_role.test_role",
						"mode": "managed",
						"type": "aws_iam_role",
						"name": "test_role",
						"provider_config_key": "aws",
						"expressions": {
							"assume_role_policy": {},
							"name": {"constant_value": "test_role"},
							"tags": {"constant_value": {"Name": "Sample-IAM-Role"}},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_sagemaker_notebook_instance.sample_ni",
						"mode": "managed",
						"type": "aws_sagemaker_notebook_instance",
						"name": "sample_ni",
						"provider_config_key": "aws",
						"expressions": {
							"direct_internet_access": {"constant_value": "Disabled"},
							"instance_type": {"constant_value": "ml.t2.medium"},
							"name": {"constant_value": "my-notebook-instance"},
							"role_arn": {"references": [
								"aws_iam_role.test_role.arn",
								"aws_iam_role.test_role",
							]},
							"tags": {"constant_value": {
								"Name": "Sample-Sagemaker-Notebook-Instance",
								"Purpose": "Policy Library Development",
							}},
						},
						"schema_version": 0,
					},
				],
				"variables": {"region": {"default": "us-west-2"}},
			},
		},
		"relevant_attributes": [{
			"resource": "aws_iam_role.test_role",
			"attribute": ["arn"],
		}],
	}
}
