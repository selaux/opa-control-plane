package global.systemtypes["terraform:2.0"].library.provider.aws.ssm.restrict_public_access.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.ssm.restrict_public_access.v1

test_restrict_public_access_good {
	account_id := "1234-5678-9012"
	in := input_ssm_document(account_id)
	actual := v1.prohibit_publicly_accessible_ssm_document with input as in
	count(actual) == 0
}

test_restrict_public_access_bad {
	account_id := "All"
	in := input_ssm_document(account_id)
	actual := v1.prohibit_publicly_accessible_ssm_document with input as in
	count(actual) == 1
}

input_ssm_document(value) = x {
	x := {
		"format_version": "1.0",
		"terraform_version": "1.1.9",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_ssm.aws_ssm_document.tf_ssm",
				"mode": "managed",
				"type": "aws_ssm_document",
				"name": "tf_ssm",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"attachments_source": [],
					"content": "  {\n    \"schemaVersion\": \"1.2\",\n    \"description\": \"Check ip configuration of a Linux instance.\",\n    \"parameters\": {\n    },\n    \"runtimeConfig\": {\n      \"aws:runShellScript\": {\n        \"properties\": [\n          {\n            \"id\": \"0.aws:runShellScript\",\n            \"runCommand\": [\"ifconfig\"]\n          }\n        ]\n      }\n    }\n  }\n",
					"document_format": "JSON",
					"document_type": "Command",
					"name": "test_document",
					"permissions": {
						"account_ids": value,
						"type": "Share",
					},
					"tags": null,
					"target_type": null,
					"version_name": null,
				},
				"sensitive_values": {
					"attachments_source": [],
					"parameter": [],
					"permissions": {},
					"platform_types": [],
					"tags_all": {},
				},
			}],
			"address": "module.sample_ssm",
		}]}},
		"resource_changes": [{
			"address": "module.sample_ssm.aws_ssm_document.tf_ssm",
			"module_address": "module.sample_ssm",
			"mode": "managed",
			"type": "aws_ssm_document",
			"name": "tf_ssm",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"attachments_source": [],
					"content": "  {\n    \"schemaVersion\": \"1.2\",\n    \"description\": \"Check ip configuration of a Linux instance.\",\n    \"parameters\": {\n    },\n    \"runtimeConfig\": {\n      \"aws:runShellScript\": {\n        \"properties\": [\n          {\n            \"id\": \"0.aws:runShellScript\",\n            \"runCommand\": [\"ifconfig\"]\n          }\n        ]\n      }\n    }\n  }\n",
					"document_format": "JSON",
					"document_type": "Command",
					"name": "test_document",
					"permissions": {
						"account_ids": value,
						"type": "Share",
					},
					"tags": null,
					"target_type": null,
					"version_name": null,
				},
				"after_unknown": {
					"arn": true,
					"attachments_source": [],
					"created_date": true,
					"default_version": true,
					"description": true,
					"document_version": true,
					"hash": true,
					"hash_type": true,
					"id": true,
					"latest_version": true,
					"owner": true,
					"parameter": true,
					"permissions": {},
					"platform_types": true,
					"schema_version": true,
					"status": true,
					"tags_all": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"attachments_source": [],
					"parameter": [],
					"permissions": {},
					"platform_types": [],
					"tags_all": {},
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.sample_ssm:aws": {
				"name": "aws",
				"version_constraint": "~> 3.27",
				"module_address": "module.sample_ssm",
				"expressions": {
					"profile": {"constant_value": "default"},
					"region": {"references": ["var.region"]},
				},
			}},
			"root_module": {"module_calls": {"sample_ssm": {
				"source": "../../../../modules/ssm",
				"module": {
					"resources": [{
						"address": "aws_ssm_document.tf_ssm",
						"mode": "managed",
						"type": "aws_ssm_document",
						"name": "tf_ssm",
						"provider_config_key": "sample_ssm:aws",
						"expressions": {
							"content": {"constant_value": "  {\n    \"schemaVersion\": \"1.2\",\n    \"description\": \"Check ip configuration of a Linux instance.\",\n    \"parameters\": {\n    },\n    \"runtimeConfig\": {\n      \"aws:runShellScript\": {\n        \"properties\": [\n          {\n            \"id\": \"0.aws:runShellScript\",\n            \"runCommand\": [\"ifconfig\"]\n          }\n        ]\n      }\n    }\n  }\n"},
							"document_type": {"constant_value": "Command"},
							"name": {"constant_value": "test_document"},
							"permissions": {"constant_value": {
								"account_ids": "All",
								"type": "Share",
							}},
						},
						"schema_version": 0,
					}],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}
