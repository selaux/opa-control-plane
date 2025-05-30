package global.systemtypes["terraform:2.0"].library.provider.aws.guardduty.guardduty_disabled.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.guardduty.guardduty_disabled.v1

test_guardduty_detector_disabled_good {
	guardduty_enabled := true
	in := input_guardduty_configuration(guardduty_enabled)
	actual := v1.prohibit_guardduty_organization_configuration_without_detector_enabled with input as in
	count(actual) == 0
}

test_guardduty_detector_disabled_bad {
	guardduty_enabled := false
	in := input_guardduty_configuration(guardduty_enabled)
	actual := v1.prohibit_guardduty_organization_configuration_without_detector_enabled with input as in
	count(actual) == 1
}

input_guardduty_configuration(guardduty_enabled) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.2",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_guardduty_detector.example",
				"mode": "managed",
				"type": "aws_guardduty_detector",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"enable": guardduty_enabled,
					"tags": null,
				},
				"sensitive_values": {
					"datasources": [],
					"tags_all": {},
				},
			},
			{
				"address": "aws_guardduty_detector.example2",
				"mode": "managed",
				"type": "aws_guardduty_detector",
				"name": "example2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"enable": true,
					"tags": null,
				},
				"sensitive_values": {
					"datasources": [],
					"tags_all": {},
				},
			},
			{
				"address": "aws_guardduty_organization_configuration.example",
				"mode": "managed",
				"type": "aws_guardduty_organization_configuration",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"auto_enable": true,
					"datasources": [{"s3_logs": [{"auto_enable": true}]}],
				},
				"sensitive_values": {"datasources": [{"s3_logs": [{}]}]},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_guardduty_detector.example",
				"mode": "managed",
				"type": "aws_guardduty_detector",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"enable": guardduty_enabled,
						"tags": null,
					},
					"after_unknown": {
						"account_id": true,
						"arn": true,
						"datasources": true,
						"finding_publishing_frequency": true,
						"id": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"datasources": [],
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_guardduty_detector.example2",
				"mode": "managed",
				"type": "aws_guardduty_detector",
				"name": "example2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"enable": true,
						"tags": null,
					},
					"after_unknown": {
						"account_id": true,
						"arn": true,
						"datasources": true,
						"finding_publishing_frequency": true,
						"id": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"datasources": [],
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_guardduty_organization_configuration.example",
				"mode": "managed",
				"type": "aws_guardduty_organization_configuration",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"auto_enable": true,
						"datasources": [{"s3_logs": [{"auto_enable": true}]}],
					},
					"after_unknown": {
						"datasources": [{"s3_logs": [{}]}],
						"detector_id": true,
						"id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"datasources": [{"s3_logs": [{}]}]},
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
						"address": "aws_guardduty_detector.example",
						"mode": "managed",
						"type": "aws_guardduty_detector",
						"name": "example",
						"provider_config_key": "aws",
						"expressions": {"enable": {"constant_value": true}},
						"schema_version": 0,
					},
					{
						"address": "aws_guardduty_detector.example2",
						"mode": "managed",
						"type": "aws_guardduty_detector",
						"name": "example2",
						"provider_config_key": "aws",
						"expressions": {"enable": {"constant_value": true}},
						"schema_version": 0,
					},
					{
						"address": "aws_guardduty_organization_configuration.example",
						"mode": "managed",
						"type": "aws_guardduty_organization_configuration",
						"name": "example",
						"provider_config_key": "aws",
						"expressions": {
							"auto_enable": {"constant_value": true},
							"datasources": [{"s3_logs": [{"auto_enable": {"constant_value": true}}]}],
							"detector_id": {"references": [
								"aws_guardduty_detector.example.id",
								"aws_guardduty_detector.example",
							]},
						},
						"schema_version": 0,
					},
				],
				"variables": {"region": {"default": "us-west-2"}},
			},
		},
		"relevant_attributes": [{
			"resource": "aws_guardduty_detector.example",
			"attribute": ["id"],
		}],
	}
}
