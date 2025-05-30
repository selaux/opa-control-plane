package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_hardcoded_credentials.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.restrict_hardcoded_credentials.v1

input_tf_json_with_credentials(expressions) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.16",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_vpc.example",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "example",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"assign_generated_ipv6_cidr_block": false,
				"cidr_block": "10.0.0.0/16",
				"enable_dns_support": true,
				"instance_tenancy": "default",
				"tags": null,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_vpc.example",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assign_generated_ipv6_cidr_block": false,
					"cidr_block": "10.0.0.0/16",
					"enable_dns_support": true,
					"instance_tenancy": "default",
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"default_network_acl_id": true,
					"default_route_table_id": true,
					"default_security_group_id": true,
					"dhcp_options_id": true,
					"enable_classiclink": true,
					"enable_classiclink_dns_support": true,
					"enable_dns_hostnames": true,
					"id": true,
					"ipv6_association_id": true,
					"ipv6_cidr_block": true,
					"main_route_table_id": true,
					"owner_id": true,
					"tags_all": true,
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": expressions,
			}},
			"root_module": {"resources": [{
				"address": "aws_vpc.example",
				"mode": "managed",
				"type": "aws_vpc",
				"name": "example",
				"provider_config_key": "aws",
				"expressions": {"cidr_block": {"constant_value": "10.0.0.0/16"}},
				"schema_version": 1,
			}]},
		},
	}
}

test_restrict_hardcoded_credentials_bad_1 {
	expressions := {
		"access_key": {"constant_value": "access_key"},
		"region": {"constant_value": "us-east-1"},
		"secret_key": {"constant_value": "secret_key"},
	}

	in := input_tf_json_with_credentials(expressions)
	actual := v1.restrict_hardcoded_credentials with input as in
	count(actual) == 2
}

test_restrict_hardcoded_credentials_bad_2 {
	expressions := {
		"region": {"constant_value": "us-east-1"},
		"secret_key": {"constant_value": "secret_key"},
	}

	in := input_tf_json_with_credentials(expressions)
	actual := v1.restrict_hardcoded_credentials with input as in
	count(actual) == 1
}

test_restrict_hardcoded_credentials_bad_3 {
	expressions := {
		"access_key": {"constant_value": "access_key"},
		"region": {"constant_value": "us-east-1"},
	}

	in := input_tf_json_with_credentials(expressions)
	actual := v1.restrict_hardcoded_credentials with input as in
	count(actual) == 1
}

test_restrict_hardcoded_credentials_good {
	expressions := {"region": {"constant_value": "us-east-1"}}

	in := input_tf_json_with_credentials(expressions)
	actual := v1.restrict_hardcoded_credentials with input as in
	count(actual) == 0
}
