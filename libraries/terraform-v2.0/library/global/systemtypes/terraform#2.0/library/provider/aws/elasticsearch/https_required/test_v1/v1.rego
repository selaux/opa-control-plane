package global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.https_required.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.elasticsearch.https_required.v1

test_enforce_https_elasticsearch_good {
	enabled := true
	policy := "Policy-Min-TLS-1-2-2019-07"
	in := input_elasticsearch_domain(enabled, policy)
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 0
}

test_enforce_https_elasticsearch_one_false_https {
	enabled := false
	policy := "Policy-Min-TLS-1-2-2019-07"
	in := input_elasticsearch_domain(enabled, policy)
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 1
}

test_enforce_https_elasticsearch_one_false_policy {
	enabled := true
	policy := "Policy-Min-TLS-1-0-2019-07"
	in := input_elasticsearch_domain(enabled, policy)
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 1
}

test_enforce_https_elasticsearch_two_false {
	enabled := false
	policy := "Policy-Min-TLS-1-0-2019-07"
	in := input_elasticsearch_domain(enabled, policy)
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 2
}

test_enforce_https_elasticsearch_not_configured {
	in := input_elasticsearch_domain_no_domain_endpoint_option_block
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 1
}

test_tls_security_policy_elasticsearch_not_configured {
	in := input_elasticsearch_domain_no_tls_security_policy_attribute
	actual := v1.prohibit_elasticsearch_domains_without_https_enforced with input as in

	count(actual) == 1
}

input_elasticsearch_domain_no_domain_endpoint_option_block = {
	"format_version": "1.1",
	"terraform_version": "1.2.4",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
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
			"domain_name": "domain1",
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
	}]}},
	"resource_changes": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
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
				"domain_name": "domain1",
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
	"configuration": {"root_module": {"resources": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
		"provider_config_key": "aws",
		"expressions": {
			"cluster_config": [{"instance_type": {"constant_value": "r4.large.elasticsearch"}}],
			"domain_name": {"constant_value": "domain1"},
			"ebs_options": [{
				"ebs_enabled": {"constant_value": true},
				"volume_size": {"constant_value": 10},
			}],
			"elasticsearch_version": {"constant_value": "7.10"},
			"tags": {"constant_value": {"Domain": "TestDomain"}},
		},
		"schema_version": 0,
	}]}},
}

input_elasticsearch_domain(a, b) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.4",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_elasticsearch_domain.elasticsearch_domain",
			"mode": "managed",
			"type": "aws_elasticsearch_domain",
			"name": "elasticsearch_domain",
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
				"domain_endpoint_options": [{
					"custom_endpoint": null,
					"custom_endpoint_certificate_arn": null,
					"custom_endpoint_enabled": false,
					"enforce_https": a,
					"tls_security_policy": b,
				}],
				"domain_name": "domain1",
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
		}]}},
		"resource_changes": [{
			"address": "aws_elasticsearch_domain.elasticsearch_domain",
			"mode": "managed",
			"type": "aws_elasticsearch_domain",
			"name": "elasticsearch_domain",
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
					"domain_endpoint_options": [{
						"custom_endpoint": null,
						"custom_endpoint_certificate_arn": null,
						"custom_endpoint_enabled": false,
						"enforce_https": a,
						"tls_security_policy": b,
					}],
					"domain_name": "domain1",
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
					"domain_endpoint_options": [{}],
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
		"configuration": {"root_module": {"resources": [{
			"address": "aws_elasticsearch_domain.elasticsearch_domain",
			"mode": "managed",
			"type": "aws_elasticsearch_domain",
			"name": "elasticsearch_domain",
			"provider_config_key": "aws",
			"expressions": {
				"cluster_config": [{"instance_type": {"constant_value": "r4.large.elasticsearch"}}],
				"domain_endpoint_options": [{
					"enforce_https": {"constant_value": a},
					"tls_security_policy": {"constant_value": b},
				}],
				"domain_name": {"constant_value": "example"},
				"ebs_options": [{
					"ebs_enabled": {"constant_value": true},
					"volume_size": {"constant_value": 10},
				}],
				"elasticsearch_version": {"constant_value": "7.10"},
				"tags": {"constant_value": {"Domain": "TestDomain"}},
			},
			"schema_version": 0,
		}]}},
	}
}

input_elasticsearch_domain_no_tls_security_policy_attribute = {
	"format_version": "1.1",
	"terraform_version": "1.2.4",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
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
			"domain_endpoint_options": [{
				"custom_endpoint": null,
				"custom_endpoint_certificate_arn": null,
				"custom_endpoint_enabled": false,
				"enforce_https": true,
			}],
			"domain_name": "domain1",
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
	}]}},
	"resource_changes": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
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
				"domain_endpoint_options": [{
					"custom_endpoint": null,
					"custom_endpoint_certificate_arn": null,
					"custom_endpoint_enabled": false,
					"enforce_https": true,
				}],
				"domain_name": "domain1",
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
				"domain_endpoint_options": [{}],
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
	"configuration": {"root_module": {"resources": [{
		"address": "aws_elasticsearch_domain.elasticsearch_domain",
		"mode": "managed",
		"type": "aws_elasticsearch_domain",
		"name": "elasticsearch_domain",
		"provider_config_key": "aws",
		"expressions": {
			"cluster_config": [{"instance_type": {"constant_value": "r4.large.elasticsearch"}}],
			"domain_endpoint_options": [{"enforce_https": {"constant_value": true}}],
			"domain_name": {"constant_value": "example"},
			"ebs_options": [{
				"ebs_enabled": {"constant_value": true},
				"volume_size": {"constant_value": 10},
			}],
			"elasticsearch_version": {"constant_value": "7.10"},
			"tags": {"constant_value": {"Domain": "TestDomain"}},
		},
		"schema_version": 0,
	}]}},
}
