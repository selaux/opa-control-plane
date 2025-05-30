package global.systemtypes["terraform:2.0"].library.provider.aws.dax.encryption_at_rest.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.dax.encryption_at_rest.v1

test_encryption_at_rest_dax_good {
	enabled := true
	in := input_dax_cluster(enabled)
	actual := v1.prohibit_dax_clusters_with_disabled_encryption_at_rest with input as in
	count(actual) == 0
}

test_encryption_at_rest_dax_bad {
	enabled := false
	in := input_dax_cluster(enabled)
	actual := v1.prohibit_dax_clusters_with_disabled_encryption_at_rest with input as in
	count(actual) == 1
}

test_encryption_at_rest_dax_not_configured {
	in := input_dax_cluster_no_block
	actual := v1.prohibit_dax_clusters_with_disabled_encryption_at_rest with input as in
	count(actual) == 1
}

input_dax_cluster_no_block = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.5",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_dax.aws_dax_cluster.sample_dax_cluster",
				"mode": "managed",
				"type": "aws_dax_cluster",
				"name": "sample_dax_cluster",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"availability_zones": null,
					"cluster_endpoint_encryption_type": null,
					"cluster_name": "sample-cluster",
					"description": null,
					"node_type": "dax.r4.large",
					"notification_topic_arn": null,
					"replication_factor": 1,
					"server_side_encryption": [],
					"tags": null,
					"timeouts": null,
				},
			}],
			"address": "module.sample_dax",
		}]}},
		"resource_changes": [{
			"address": "module.sample_dax.aws_dax_cluster.sample_dax_cluster",
			"module_address": "module.sample_dax",
			"mode": "managed",
			"type": "aws_dax_cluster",
			"name": "sample_dax_cluster",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"availability_zones": null,
					"cluster_endpoint_encryption_type": null,
					"cluster_name": "sample-cluster",
					"description": null,
					"node_type": "dax.r4.large",
					"notification_topic_arn": null,
					"replication_factor": 1,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"cluster_address": true,
					"configuration_endpoint": true,
					"iam_role_arn": true,
					"id": true,
					"maintenance_window": true,
					"nodes": true,
					"parameter_group_name": true,
					"port": true,
					"security_group_ids": true,
					"server_side_encryption": [],
					"subnet_group_name": true,
					"tags_all": true,
				},
			},
		}],
		"configuration": {"root_module": {"module_calls": {"sample_dax": {
			"source": "../../../../modules/dax",
			"module": {
				"resources": [{
					"address": "aws_dax_cluster.sample_dax_cluster",
					"mode": "managed",
					"type": "aws_dax_cluster",
					"name": "sample_dax_cluster",
					"provider_config_key": "module.sample_dax:aws",
					"expressions": {
						"cluster_name": {"constant_value": "sample-cluster"},
						"iam_role_arn": {"references": [
							"aws_iam_role.test_role.arn",
							"aws_iam_role.test_role",
						]},
						"node_type": {"constant_value": "dax.r4.large"},
						"replication_factor": {"constant_value": 1},
						"server_side_encryption": [{"enabled": {"constant_value": true}}],
					},
					"schema_version": 0,
				}],
				"variables": {
					"asg_name": {
						"default": "tf-asg-styra",
						"description": "Name of the autoscaling group",
					},
					"aws_region": {
						"default": "us-west-2",
						"description": "AWS region",
					},
					"instance_type": {
						"default": "m6a.large",
						"description": "Type of the instance for launch configuration",
					},
					"launch_conf_name": {
						"default": "tf-launchconf-styra",
						"description": "Name of the launch configuration",
					},
				},
			},
		}}}},
		"relevant_attributes": [{
			"resource": "module.sample_dax.aws_iam_role.test_role",
			"attribute": ["arn"],
		}],
	}
}

input_dax_cluster(value) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.3.6",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_dax_cluster.sample_dax_cluster",
				"mode": "managed",
				"type": "aws_dax_cluster",
				"name": "sample_dax_cluster",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"availability_zones": null,
					"cluster_endpoint_encryption_type": null,
					"cluster_name": "sample-cluster",
					"description": null,
					"node_type": "dax.r4.large",
					"notification_topic_arn": null,
					"replication_factor": 1,
					"server_side_encryption": [{"enabled": value}],
					"tags": null,
					"timeouts": null,
				},
				"sensitive_values": {
					"nodes": [],
					"security_group_ids": [],
					"server_side_encryption": [{}],
					"tags_all": {},
				},
			},
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"dax.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
					"path": "/",
					"permissions_boundary": null,
					"tags": {"tag-key": "tag-value"},
					"tags_all": {"tag-key": "tag-value"},
				},
				"sensitive_values": {
					"inline_policy": [],
					"managed_policy_arns": [],
					"tags": {},
					"tags_all": {},
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_dax_cluster.sample_dax_cluster",
				"mode": "managed",
				"type": "aws_dax_cluster",
				"name": "sample_dax_cluster",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"availability_zones": null,
						"cluster_endpoint_encryption_type": null,
						"cluster_name": "sample-cluster",
						"description": null,
						"node_type": "dax.r4.large",
						"notification_topic_arn": null,
						"replication_factor": 1,
						"server_side_encryption": [{"enabled": value}],
						"tags": null,
						"timeouts": null,
					},
					"after_unknown": {
						"arn": true,
						"cluster_address": true,
						"configuration_endpoint": true,
						"iam_role_arn": true,
						"id": true,
						"maintenance_window": true,
						"nodes": true,
						"parameter_group_name": true,
						"port": true,
						"security_group_ids": true,
						"server_side_encryption": [{}],
						"subnet_group_name": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"nodes": [],
						"security_group_ids": [],
						"server_side_encryption": [{}],
						"tags_all": {},
					},
				},
			},
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
						"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"dax.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
						"description": null,
						"force_detach_policies": false,
						"max_session_duration": 3600,
						"name": "test_role",
						"path": "/",
						"permissions_boundary": null,
						"tags": {"tag-key": "tag-value"},
						"tags_all": {"tag-key": "tag-value"},
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
		],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {
				"resources": [
					{
						"address": "aws_dax_cluster.sample_dax_cluster",
						"mode": "managed",
						"type": "aws_dax_cluster",
						"name": "sample_dax_cluster",
						"provider_config_key": "aws",
						"expressions": {
							"cluster_name": {"constant_value": "sample-cluster"},
							"iam_role_arn": {"references": [
								"aws_iam_role.test_role.arn",
								"aws_iam_role.test_role",
							]},
							"node_type": {"constant_value": "dax.r4.large"},
							"replication_factor": {"constant_value": 1},
							"server_side_encryption": [{"enabled": {"constant_value": true}}],
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
							"tags": {"constant_value": {"tag-key": "tag-value"}},
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
