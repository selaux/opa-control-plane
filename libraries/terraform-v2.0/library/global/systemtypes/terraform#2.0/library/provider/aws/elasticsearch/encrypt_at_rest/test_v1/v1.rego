package global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.encrypt_at_rest.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.encrypt_at_rest.v1

test_encrypt_at_rest_elasticsearch_good {
	enabled := true
	in := input_elasticsearch_domain(enabled)
	actual := v1.prohibit_elasticsearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 0
}

test_encrypt_at_rest_elasticsearch_bad {
	enabled := false
	in := input_elasticsearch_domain(enabled)
	actual := v1.prohibit_elasticsearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 1
}

test_encrypt_at_rest_elasticsearch_not_configured {
	in := input_elasticsearch_domain_no_block
	actual := v1.prohibit_elasticsearch_domains_with_disabled_encrypt_at_rest with input as in

	count(actual) == 1
}

input_elasticsearch_domain_no_block = {
	"format_version": "1.1",
	"terraform_version": "1.2.3",
	"planned_values": {"root_module": {"child_modules": [{
		"resources": [{
			"address": "module.sample_elastic_search_domain.aws_elasticsearch_domain.elasticsearch_example",
			"mode": "managed",
			"type": "aws_elasticsearch_domain",
			"name": "elasticsearch_example",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"cluster_config": [{
					"dedicated_master_count": null,
					"dedicated_master_enabled": false,
					"dedicated_master_type": null,
					"instance_count": 1,
					"instance_type": "r4.large.elasticsearch",
					"warm_count": null,
					"warm_enabled": null,
					"warm_type": null,
					"zone_awareness_config": [],
					"zone_awareness_enabled": null,
				}],
				"cognito_options": [],
				"domain_name": "example-domain",
				"ebs_options": [{
					"ebs_enabled": true,
					"iops": null,
					"volume_size": 10,
				}],
				"elasticsearch_version": "7.10",
				"log_publishing_options": [],
				"snapshot_options": [],
				"tags": {"Domain": "TestDomain"},
				"tags_all": {"Domain": "TestDomain"},
				"timeouts": null,
				"vpc_options": [],
			},
		}],
		"address": "module.sample_elastic_search_domain",
	}]}},
	"resource_changes": [{
		"address": "module.sample_elastic_search_domain.aws_elasticsearch_domain.elasticsearch_example",
		"module_address": "module.sample_elastic_search_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_example",
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
					"instance_type": "r4.large.elasticsearch",
					"warm_count": null,
					"warm_enabled": null,
					"warm_type": null,
					"zone_awareness_config": [],
					"zone_awareness_enabled": null,
				}],
				"cognito_options": [],
				"domain_name": "example-domain",
				"ebs_options": [{
					"ebs_enabled": true,
					"iops": null,
					"volume_size": 10,
				}],
				"elasticsearch_version": "7.10",
				"log_publishing_options": [],
				"snapshot_options": [],
				"tags": {"Domain": "TestDomain"},
				"tags_all": {"Domain": "TestDomain"},
				"timeouts": null,
				"vpc_options": [],
			},
		},
	}],
	"configuration": {"root_module": {"module_calls": {"sample_elastic_search_domain": {
		"source": "../../../../modules/elasticsearch",
		"module": {
			"resources": [{
				"address": "aws_elasticsearch_domain.elasticsearch_example",
				"mode": "managed",
				"type": "aws_elasticsearch_domain",
				"name": "elasticsearch_example",
				"provider_config_key": "module.sample_elastic_search_domain:aws",
				"expressions": {
					"cluster_config": [{"instance_type": {"constant_value": "r4.large.elasticsearch"}}],
					"domain_name": {"constant_value": "example-domain"},
					"ebs_options": [{
						"ebs_enabled": {"constant_value": true},
						"volume_size": {"constant_value": 10},
					}],
					"elasticsearch_version": {"constant_value": "7.10"},
					"tags": {"constant_value": {"Domain": "TestDomain"}},
				},
				"schema_version": 0,
			}],
			"variables": {"region": {"default": "us-west-2"}},
		},
	}}}},
}

input_elasticsearch_domain(value) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.3",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [{
				"address": "module.sample_elastic_search_domain.aws_elasticsearch_domain.elasticsearch_example",
				"mode": "managed",
				"type": "aws_elasticsearch_domain",
				"name": "elasticsearch_example",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"cluster_config": [{
						"dedicated_master_count": null,
						"dedicated_master_enabled": false,
						"dedicated_master_type": null,
						"instance_count": 1,
						"instance_type": "r4.large.elasticsearch",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "example-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"iops": null,
						"volume_size": 10,
					}],
					"elasticsearch_version": "7.10",
					"encrypt_at_rest": [{"enabled": value}],
					"log_publishing_options": [],
					"snapshot_options": [],
					"tags": {"Domain": "TestDomain"},
					"tags_all": {"Domain": "TestDomain"},
					"timeouts": null,
					"vpc_options": [],
				},
			}],
			"address": "module.sample_elastic_search_domain",
		}]}},
		"resource_changes": [{
			"address": "module.sample_elastic_search_domain.aws_elasticsearch_domain.elasticsearch_example",
			"module_address": "module.sample_elastic_search_domain",
			"mode": "managed",
			"type": "aws_elasticsearch_domain",
			"name": "elasticsearch_example",
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
						"instance_type": "r4.large.elasticsearch",
						"warm_count": null,
						"warm_enabled": null,
						"warm_type": null,
						"zone_awareness_config": [],
						"zone_awareness_enabled": null,
					}],
					"cognito_options": [],
					"domain_name": "example-domain",
					"ebs_options": [{
						"ebs_enabled": true,
						"iops": null,
						"volume_size": 10,
					}],
					"elasticsearch_version": "7.10",
					"encrypt_at_rest": [{"enabled": value}],
					"log_publishing_options": [],
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
					"cluster_config": [{"zone_awareness_config": []}],
					"cognito_options": [],
					"domain_endpoint_options": true,
					"domain_id": true,
					"ebs_options": [{"volume_type": true}],
					"encrypt_at_rest": true,
					"endpoint": true,
					"id": true,
					"kibana_endpoint": true,
					"log_publishing_options": [],
					"node_to_node_encryption": true,
					"snapshot_options": [],
					"tags": {},
					"tags_all": {},
					"vpc_options": [],
				},
			},
		}],
		"configuration": {"root_module": {"module_calls": {"sample_elastic_search_domain": {
			"source": "../../../../modules/elasticsearch",
			"module": {
				"resources": [{
					"address": "aws_elasticsearch_domain.elasticsearch_example",
					"mode": "managed",
					"type": "aws_elasticsearch_domain",
					"name": "elasticsearch_example",
					"provider_config_key": "module.sample_elastic_search_domain:aws",
					"expressions": {
						"cluster_config": [{"instance_type": {"constant_value": "r4.large.elasticsearch"}}],
						"domain_name": {"constant_value": "example-domain"},
						"ebs_options": [{
							"ebs_enabled": {"constant_value": true},
							"volume_size": {"constant_value": 10},
						}],
						"elasticsearch_version": {"constant_value": "7.10"},
						"encrypt_at_rest": [{"enabled": {"constant_value": true}}],
						"tags": {"constant_value": {"Domain": "TestDomain"}},
					},
					"schema_version": 0,
				}],
				"variables": {"region": {"default": "us-west-2"}},
			},
		}}}},
	}
}
