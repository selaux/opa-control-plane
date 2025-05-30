package global.systemtypes["terraform:2.0"].library.provider.aws.opensearch.encrypt_at_rest.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.opensearch.encrypt_at_rest.v1

test_encrypt_at_rest_opensearch_good {
	enabled := true
	in := input_opensearch_domain(enabled)
	actual := v1.prohibit_opensearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 0
}

test_encrypt_at_rest_opensearch_bad {
	enabled := false
	in := input_opensearch_domain(enabled)
	actual := v1.prohibit_opensearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 1
}

test_encrypt_at_rest_opensearch_not_configured {
	in := input_opensearch_domain_no_block
	actual := v1.prohibit_opensearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 1
}

input_opensearch_domain_no_block := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_opensearch_domain.aws_opensearch_domain.example",
				"mode": "managed",
				"type": "aws_opensearch_domain",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"cluster_config": [{
						"dedicated_master_count": null,
						"dedicated_master_enabled": false,
						"dedicated_master_type": null,
						"instance_count": 1,
						"instance_type": "r4.large.search",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "opensearch-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"volume_size": 10,
					}],
					"engine_version": "OpenSearch_1.1",
					"log_publishing_options": [],
					"node_to_node_encryption": [{"enabled": true}],
					"snapshot_options": [],
					"tags": {"Domain": "TestDomain"},
					"tags_all": {"Domain": "TestDomain"},
					"timeouts": null,
					"vpc_options": [],
				},
				"sensitive_values": {
					"advanced_options": {},
					"advanced_security_options": [],
					"auto_tune_options": [],
					"cluster_config": [{
						"cold_storage_options": [],
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": [],
					"ebs_options": [{}],
					"encrypt_at_rest": [],
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
			}],
			"address": "module.sample_opensearch_domain",
		}]}},
		"resource_changes": [{
			"address": "module.sample_opensearch_domain.aws_opensearch_domain.example",
			"module_address": "module.sample_opensearch_domain",
			"mode": "managed",
			"type": "aws_opensearch_domain",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"cluster_config": [{
						"dedicated_master_count": null,
						"dedicated_master_enabled": false,
						"dedicated_master_type": null,
						"instance_count": 1,
						"instance_type": "r4.large.search",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "opensearch-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"volume_size": 10,
					}],
					"engine_version": "OpenSearch_1.1",
					"log_publishing_options": [],
					"node_to_node_encryption": [{"enabled": true}],
					"snapshot_options": [],
					"tags": {"Domain": "TestDomain"},
					"tags_all": {"Domain": "TestDomain"},
					"timeouts": null,
					"vpc_options": [],
				},
				"after_unknown": {
					"access_policies": true,
					"advanced_options": true,
					"advanced_security_options": true,
					"arn": true,
					"auto_tune_options": true,
					"cluster_config": [{
						"cold_storage_options": true,
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": true,
					"domain_id": true,
					"ebs_options": [{
						"iops": true,
						"throughput": true,
						"volume_type": true,
					}],
					"encrypt_at_rest": true,
					"endpoint": true,
					"id": true,
					"kibana_endpoint": true,
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
				"before_sensitive": false,
				"after_sensitive": {
					"advanced_options": {},
					"advanced_security_options": [],
					"auto_tune_options": [],
					"cluster_config": [{
						"cold_storage_options": [],
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": [],
					"ebs_options": [{}],
					"encrypt_at_rest": [],
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.sample_opensearch_domain:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.sample_opensearch_domain",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {"module_calls": {"sample_opensearch_domain": {
				"source": "../../../../../modules/opensearch",
				"module": {
					"resources": [{
						"address": "aws_opensearch_domain.example",
						"mode": "managed",
						"type": "aws_opensearch_domain",
						"name": "example",
						"provider_config_key": "module.sample_opensearch_domain:aws",
						"expressions": {
							"cluster_config": [{"instance_type": {"constant_value": "r4.large.search"}}],
							"domain_name": {"constant_value": "opensearch-domain"},
							"ebs_options": [{
								"ebs_enabled": {"constant_value": true},
								"volume_size": {"constant_value": 10},
							}],
							"node_to_node_encryption": [{"enabled": {"constant_value": true}}],
							"tags": {"constant_value": {"Domain": "TestDomain"}},
						},
						"schema_version": 0,
					}],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}

input_opensearch_domain(value) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_opensearch_domain.aws_opensearch_domain.example",
				"mode": "managed",
				"type": "aws_opensearch_domain",
				"name": "example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"cluster_config": [{
						"dedicated_master_count": null,
						"dedicated_master_enabled": false,
						"dedicated_master_type": null,
						"instance_count": 1,
						"instance_type": "r4.large.search",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "opensearch-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"volume_size": 10,
					}],
					"encrypt_at_rest": [{"enabled": value}],
					"engine_version": "OpenSearch_1.1",
					"log_publishing_options": [],
					"node_to_node_encryption": [{"enabled": true}],
					"snapshot_options": [],
					"tags": {"Domain": "TestDomain"},
					"tags_all": {"Domain": "TestDomain"},
					"timeouts": null,
					"vpc_options": [],
				},
				"sensitive_values": {
					"advanced_options": {},
					"advanced_security_options": [],
					"auto_tune_options": [],
					"cluster_config": [{
						"cold_storage_options": [],
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": [],
					"ebs_options": [{}],
					"encrypt_at_rest": [{}],
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
			}],
			"address": "module.sample_opensearch_domain",
		}]}},
		"resource_changes": [{
			"address": "module.sample_opensearch_domain.aws_opensearch_domain.example",
			"module_address": "module.sample_opensearch_domain",
			"mode": "managed",
			"type": "aws_opensearch_domain",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"cluster_config": [{
						"dedicated_master_count": null,
						"dedicated_master_enabled": false,
						"dedicated_master_type": null,
						"instance_count": 1,
						"instance_type": "r4.large.search",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "opensearch-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"volume_size": 10,
					}],
					"encrypt_at_rest": [{"enabled": value}],
					"engine_version": "OpenSearch_1.1",
					"log_publishing_options": [],
					"node_to_node_encryption": [{"enabled": true}],
					"snapshot_options": [],
					"tags": {"Domain": "TestDomain"},
					"tags_all": {"Domain": "TestDomain"},
					"timeouts": null,
					"vpc_options": [],
				},
				"after_unknown": {
					"access_policies": true,
					"advanced_options": true,
					"advanced_security_options": true,
					"arn": true,
					"auto_tune_options": true,
					"cluster_config": [{
						"cold_storage_options": true,
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": true,
					"domain_id": true,
					"ebs_options": [{
						"iops": true,
						"throughput": true,
						"volume_type": true,
					}],
					"encrypt_at_rest": [{"kms_key_id": true}],
					"endpoint": true,
					"id": true,
					"kibana_endpoint": true,
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
				"before_sensitive": false,
				"after_sensitive": {
					"advanced_options": {},
					"advanced_security_options": [],
					"auto_tune_options": [],
					"cluster_config": [{
						"cold_storage_options": [],
						"zone_awareness_config": [],
					}],
					"cognito_options": [],
					"domain_endpoint_options": [],
					"ebs_options": [{}],
					"encrypt_at_rest": [{}],
					"log_publishing_options": [],
					"node_to_node_encryption": [{}],
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
			},
		}],
		"configuration": {
			"provider_config": {"module.sample_opensearch_domain:aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"module_address": "module.sample_opensearch_domain",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {"module_calls": {"sample_opensearch_domain": {
				"source": "../../../../../modules/opensearch",
				"module": {
					"resources": [{
						"address": "aws_opensearch_domain.example",
						"mode": "managed",
						"type": "aws_opensearch_domain",
						"name": "example",
						"provider_config_key": "module.sample_opensearch_domain:aws",
						"expressions": {
							"cluster_config": [{"instance_type": {"constant_value": "r4.large.search"}}],
							"domain_name": {"constant_value": "opensearch-domain"},
							"ebs_options": [{
								"ebs_enabled": {"constant_value": true},
								"volume_size": {"constant_value": 10},
							}],
							"encrypt_at_rest": [{"enabled": {"constant_value": true}}],
							"node_to_node_encryption": [{"enabled": {"constant_value": true}}],
							"tags": {"constant_value": {"Domain": "TestDomain"}},
						},
						"schema_version": 0,
					}],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
	}
}
