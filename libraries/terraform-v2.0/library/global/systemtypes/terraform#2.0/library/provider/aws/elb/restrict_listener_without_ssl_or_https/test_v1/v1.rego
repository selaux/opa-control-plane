package global.systemtypes["terraform:2.0"].library.provider.aws.elb.restrict_listener_without_ssl_or_https.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.elb.restrict_listener_without_ssl_or_https.v1

input_listener(protocol1, protocol2) := x {
	x := [
		{
			"instance_port": 8000,
			"instance_protocol": "http",
			"lb_port": 443,
			"lb_protocol": protocol1,
			"ssl_certificate_id": "arn:aws:iam::123456789012:server-certificate/certName",
		},
		{
			"instance_port": 8000,
			"instance_protocol": "http",
			"lb_port": 80,
			"lb_protocol": protocol2,
			"ssl_certificate_id": "",
		},
	]
}

test_no_listener_good {
	listener := []
	in := input_elastic_loadbalancer(listener)
	actual := v1.prohibit_elastic_load_balancer_without_lb_protocol_ssl_or_https with input as in
	count(actual) == 0
}

test_listener_with_ssl_or_https_good {
	protocol1 := "ssl"
	protocol2 := "https"

	listener := input_listener(protocol1, protocol2)

	in := input_elastic_loadbalancer(listener)
	actual := v1.prohibit_elastic_load_balancer_without_lb_protocol_ssl_or_https with input as in
	count(actual) == 0
}

test_listener_without_ssl_or_https_one_bad {
	protocol1 := "http"
	protocol2 := "https"

	listener := input_listener(protocol1, protocol2)

	in := input_elastic_loadbalancer(listener)
	actual := v1.prohibit_elastic_load_balancer_without_lb_protocol_ssl_or_https with input as in
	count(actual) == 1
}

test_listener_without_ssl_or_https_two_bad {
	protocol1 := "http"
	protocol2 := "TCP"

	listener := input_listener(protocol1, protocol2)

	in := input_elastic_loadbalancer(listener)
	actual := v1.prohibit_elastic_load_balancer_without_lb_protocol_ssl_or_https with input as in
	count(actual) == 2
}

input_elastic_loadbalancer(listener) := x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.7",
		"planned_values": {"root_module": {"child_modules": [{
			"resources": [
				{
					"address": "module.sample_elb.aws_elb.sample_elb",
					"mode": "managed",
					"type": "aws_elb",
					"name": "sample_elb",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"access_logs": [{
							"bucket_prefix": "tfelb",
							"enabled": true,
							"interval": 60,
						}],
						"availability_zones": [
							"us-west-2a",
							"us-west-2b",
							"us-west-2c",
						],
						"connection_draining": true,
						"connection_draining_timeout": 400,
						"cross_zone_load_balancing": true,
						"desync_mitigation_mode": "defensive",
						"health_check": [{
							"healthy_threshold": 2,
							"interval": 30,
							"target": "HTTP:8000/",
							"timeout": 3,
							"unhealthy_threshold": 2,
						}],
						"idle_timeout": 400,
						"listener": listener,
						"name": "sample-terraform-elb",
						"name_prefix": null,
						"tags": {"Name": "foobar-terraform-elb"},
						"tags_all": {"Name": "foobar-terraform-elb"},
					},
					"sensitive_values": {
						"access_logs": [{}],
						"availability_zones": [
							false,
							false,
							false,
						],
						"health_check": [{}],
						"instances": [],
						"listener": [
							{},
							{},
						],
						"security_groups": [],
						"subnets": [],
						"tags": {},
						"tags_all": {},
					},
				},
				{
					"address": "module.sample_elb.aws_s3_bucket.tf_sample_log_s3",
					"mode": "managed",
					"type": "aws_s3_bucket",
					"name": "tf_sample_log_s3",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": {
							"Name": "My Log Bucket",
							"Purpose": "Policy Library Development",
						},
						"tags_all": {
							"Name": "My Log Bucket",
							"Purpose": "Policy Library Development",
						},
						"timeouts": null,
					},
					"sensitive_values": {
						"cors_rule": [],
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {},
						"tags_all": {},
						"versioning": [],
						"website": [],
					},
				},
				{
					"address": "module.sample_elb.random_string.random_s3_log_val",
					"mode": "managed",
					"type": "random_string",
					"name": "random_s3_log_val",
					"provider_name": "registry.terraform.io/hashicorp/random",
					"schema_version": 2,
					"values": {
						"keepers": null,
						"length": 4,
						"lower": true,
						"min_lower": 0,
						"min_numeric": 0,
						"min_special": 0,
						"min_upper": 0,
						"number": true,
						"numeric": true,
						"override_special": ".-",
						"special": true,
						"upper": false,
					},
					"sensitive_values": {},
				},
			],
			"address": "module.sample_elb",
		}]}},
		"resource_changes": [
			{
				"address": "module.sample_elb.aws_elb.sample_elb",
				"module_address": "module.sample_elb",
				"mode": "managed",
				"type": "aws_elb",
				"name": "sample_elb",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"access_logs": [{
							"bucket_prefix": "tfelb",
							"enabled": true,
							"interval": 60,
						}],
						"availability_zones": [
							"us-west-2a",
							"us-west-2b",
							"us-west-2c",
						],
						"connection_draining": true,
						"connection_draining_timeout": 400,
						"cross_zone_load_balancing": true,
						"desync_mitigation_mode": "defensive",
						"health_check": [{
							"healthy_threshold": 2,
							"interval": 30,
							"target": "HTTP:8000/",
							"timeout": 3,
							"unhealthy_threshold": 2,
						}],
						"idle_timeout": 400,
						"listener": listener,
						"name": "sample-terraform-elb",
						"name_prefix": null,
						"tags": {"Name": "foobar-terraform-elb"},
						"tags_all": {"Name": "foobar-terraform-elb"},
					},
					"after_unknown": {
						"access_logs": [{"bucket": true}],
						"arn": true,
						"availability_zones": [
							false,
							false,
							false,
						],
						"dns_name": true,
						"health_check": [{}],
						"id": true,
						"instances": true,
						"internal": true,
						"listener": [
							{},
							{},
						],
						"security_groups": true,
						"source_security_group": true,
						"source_security_group_id": true,
						"subnets": true,
						"tags": {},
						"tags_all": {},
						"zone_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"access_logs": [{}],
						"availability_zones": [
							false,
							false,
							false,
						],
						"health_check": [{}],
						"instances": [],
						"listener": [
							{},
							{},
						],
						"security_groups": [],
						"subnets": [],
						"tags": {},
						"tags_all": {},
					},
				},
			},
			{
				"address": "module.sample_elb.aws_s3_bucket.tf_sample_log_s3",
				"module_address": "module.sample_elb",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "tf_sample_log_s3",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"bucket_prefix": null,
						"force_destroy": false,
						"tags": {
							"Name": "My Log Bucket",
							"Purpose": "Policy Library Development",
						},
						"tags_all": {
							"Name": "My Log Bucket",
							"Purpose": "Policy Library Development",
						},
						"timeouts": null,
					},
					"after_unknown": {
						"acceleration_status": true,
						"acl": true,
						"arn": true,
						"bucket": true,
						"bucket_domain_name": true,
						"bucket_regional_domain_name": true,
						"cors_rule": true,
						"grant": true,
						"hosted_zone_id": true,
						"id": true,
						"lifecycle_rule": true,
						"logging": true,
						"object_lock_configuration": true,
						"object_lock_enabled": true,
						"policy": true,
						"region": true,
						"replication_configuration": true,
						"request_payer": true,
						"server_side_encryption_configuration": true,
						"tags": {},
						"tags_all": {},
						"versioning": true,
						"website": true,
						"website_domain": true,
						"website_endpoint": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"cors_rule": [],
						"grant": [],
						"lifecycle_rule": [],
						"logging": [],
						"object_lock_configuration": [],
						"replication_configuration": [],
						"server_side_encryption_configuration": [],
						"tags": {},
						"tags_all": {},
						"versioning": [],
						"website": [],
					},
				},
			},
			{
				"address": "module.sample_elb.random_string.random_s3_log_val",
				"module_address": "module.sample_elb",
				"mode": "managed",
				"type": "random_string",
				"name": "random_s3_log_val",
				"provider_name": "registry.terraform.io/hashicorp/random",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"keepers": null,
						"length": 4,
						"lower": true,
						"min_lower": 0,
						"min_numeric": 0,
						"min_special": 0,
						"min_upper": 0,
						"number": true,
						"numeric": true,
						"override_special": ".-",
						"special": true,
						"upper": false,
					},
					"after_unknown": {
						"id": true,
						"result": true,
					},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
		],
		"configuration": {
			"provider_config": {
				"module.sample_elb:aws": {
					"name": "aws",
					"full_name": "registry.terraform.io/hashicorp/aws",
					"version_constraint": "~> 4.0",
					"module_address": "module.sample_elb",
					"expressions": {"region": {"references": ["var.region"]}},
				},
				"module.sample_elb:random": {
					"name": "random",
					"full_name": "registry.terraform.io/hashicorp/random",
					"version_constraint": "~> 3.1",
					"module_address": "module.sample_elb",
				},
			},
			"root_module": {"module_calls": {"sample_elb": {
				"source": "../../../../../modules/elb",
				"module": {
					"resources": [
						{
							"address": "aws_elb.sample_elb",
							"mode": "managed",
							"type": "aws_elb",
							"name": "sample_elb",
							"provider_config_key": "module.sample_elb:aws",
							"expressions": {
								"access_logs": [{
									"bucket": {"references": [
										"aws_s3_bucket.tf_sample_log_s3.bucket",
										"aws_s3_bucket.tf_sample_log_s3",
									]},
									"bucket_prefix": {"constant_value": "tfelb"},
									"enabled": {"constant_value": true},
									"interval": {"constant_value": 60},
								}],
								"availability_zones": {"constant_value": [
									"us-west-2a",
									"us-west-2b",
									"us-west-2c",
								]},
								"connection_draining": {"constant_value": true},
								"connection_draining_timeout": {"constant_value": 400},
								"cross_zone_load_balancing": {"constant_value": true},
								"health_check": [{
									"healthy_threshold": {"constant_value": 2},
									"interval": {"constant_value": 30},
									"target": {"constant_value": "HTTP:8000/"},
									"timeout": {"constant_value": 3},
									"unhealthy_threshold": {"constant_value": 2},
								}],
								"idle_timeout": {"constant_value": 400},
								"listener": [
									{
										"instance_port": {"constant_value": 8000},
										"instance_protocol": {"constant_value": "http"},
										"lb_port": {"constant_value": 80},
										"lb_protocol": {"constant_value": "http"},
									},
									{
										"instance_port": {"constant_value": 8000},
										"instance_protocol": {"constant_value": "http"},
										"lb_port": {"constant_value": 443},
										"lb_protocol": {"constant_value": "https"},
										"ssl_certificate_id": {"constant_value": "arn:aws:iam::123456789012:server-certificate/certName"},
									},
								],
								"name": {"constant_value": "sample-terraform-elb"},
								"tags": {"constant_value": {"Name": "foobar-terraform-elb"}},
							},
							"schema_version": 0,
						},
						{
							"address": "aws_s3_bucket.tf_sample_log_s3",
							"mode": "managed",
							"type": "aws_s3_bucket",
							"name": "tf_sample_log_s3",
							"provider_config_key": "module.sample_elb:aws",
							"expressions": {
								"bucket": {"references": ["local.log_bucket_name"]},
								"tags": {"constant_value": {
									"Name": "My Log Bucket",
									"Purpose": "Policy Library Development",
								}},
							},
							"schema_version": 0,
						},
						{
							"address": "random_string.random_s3_log_val",
							"mode": "managed",
							"type": "random_string",
							"name": "random_s3_log_val",
							"provider_config_key": "module.sample_elb:random",
							"expressions": {
								"length": {"constant_value": 4},
								"override_special": {"constant_value": ".-"},
								"special": {"constant_value": true},
								"upper": {"constant_value": false},
							},
							"schema_version": 2,
						},
					],
					"variables": {"region": {"default": "us-west-2"}},
				},
			}}},
		},
		"relevant_attributes": [
			{
				"resource": "module.sample_elb.random_string.random_s3_log_val",
				"attribute": ["result"],
			},
			{
				"resource": "module.sample_elb.aws_s3_bucket.tf_sample_log_s3",
				"attribute": ["bucket"],
			},
		],
	}
}
