package global.systemtypes["terraform:2.0"].library.provider.gcp.database.authorization.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.database.authorization.v1 as authorization

############################
# unit tests
test_prohibit_dataset_with_allauthenticatedusers_access_good {
	access_config = [{"domain": "hashicorp.com", "group_by_email": "", "role": "OWNER", "special_group": "", "user_by_email": "", "view": []}]
	in = input_with_google_bigquery_dataset_resource(access_config)
	actual := authorization.prohibit_dataset_with_allauthenticatedusers_access with input as in
	count(actual) == 0
}

test_prohibit_dataset_with_allauthenticatedusers_access_bad {
	access_config = [{"domain": "", "group_by_email": "", "role": "OWNER", "special_group": "allAuthenticatedUsers", "user_by_email": "", "view": []}]
	in = input_with_google_bigquery_dataset_resource(access_config)
	actual := authorization.prohibit_dataset_with_allauthenticatedusers_access with input as in
	count(actual) == 1
}

test_prohibit_dataset_access_with_allauthenticatedusers_access_good {
	access_config = "projectOwners"
	in = input_with_google_bigquery_dataset_access_resource(access_config)
	actual := authorization.prohibit_dataset_with_allauthenticatedusers_access with input as in
	count(actual) == 0
}

test_prohibit_dataset_access_with_allauthenticatedusers_access_bad {
	access_config = "allAuthenticatedUsers"
	in = input_with_google_bigquery_dataset_access_resource(access_config)
	actual := authorization.prohibit_dataset_with_allauthenticatedusers_access with input as in
	count(actual) == 1
}

#################
# test input data
input_with_google_bigquery_dataset_resource(access_config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.15",
		"planned_values": {"root_module": {"resources": [{
			"address": "google_bigquery_dataset.dataset",
			"mode": "managed",
			"type": "google_bigquery_dataset",
			"name": "dataset",
			"provider_name": "google",
			"schema_version": 0,
			"values": {
				"access": access_config,
				"dataset_id": "example_dataset",
				"default_encryption_configuration": [],
				"default_partition_expiration_ms": null,
				"default_table_expiration_ms": 3600000,
				"delete_contents_on_destroy": false,
				"description": "This is a test description",
				"friendly_name": "test",
				"labels": {"env": "default"},
				"location": "EU",
				"timeouts": null,
			},
		}]}},
		"resource_changes": [{
			"address": "google_bigquery_dataset.dataset",
			"mode": "managed",
			"type": "google_bigquery_dataset",
			"name": "dataset",
			"provider_name": "google",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access": access_config,
					"dataset_id": "example_dataset",
					"default_encryption_configuration": [],
					"default_partition_expiration_ms": null,
					"default_table_expiration_ms": 3600000,
					"delete_contents_on_destroy": false,
					"description": "This is a test description",
					"friendly_name": "test",
					"labels": {"env": "default"},
					"location": "EU",
					"timeouts": null,
				},
				"after_unknown": {
					"access": [
						{"view": []},
						{"view": []},
					],
					"creation_time": true,
					"default_encryption_configuration": [],
					"etag": true,
					"id": true,
					"labels": {},
					"last_modified_time": true,
					"project": true,
					"self_link": true,
				},
			},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "google_bigquery_dataset.dataset",
			"mode": "managed",
			"type": "google_bigquery_dataset",
			"name": "dataset",
			"provider_config_key": "google",
			"expressions": {
				"access": [
					{
						"role": {"constant_value": "OWNER"},
						"special_group": {"constant_value": "allAuthenticatedUsers"},
					},
					{
						"domain": {"constant_value": "hashicorp.com"},
						"role": {"constant_value": "READER"},
					},
				],
				"dataset_id": {"constant_value": "example_dataset"},
				"default_table_expiration_ms": {"constant_value": 3600000},
				"description": {"constant_value": "This is a test description"},
				"friendly_name": {"constant_value": "test"},
				"labels": {"constant_value": {"env": "default"}},
				"location": {"constant_value": "EU"},
			},
			"schema_version": 0,
		}]}},
	}
}

input_with_google_bigquery_dataset_access_resource(access_config) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.2.3",
		"planned_values": {"root_module": {"resources": [
			{
				"address": "google_bigquery_dataset.dataset_with_access",
				"mode": "managed",
				"type": "google_bigquery_dataset",
				"name": "dataset_with_access",
				"provider_name": "registry.terraform.io/hashicorp/google",
				"schema_version": 0,
				"values": {
					"dataset_id": "dataset_with_access",
					"default_encryption_configuration": [],
					"default_partition_expiration_ms": null,
					"default_table_expiration_ms": null,
					"delete_contents_on_destroy": false,
					"description": null,
					"friendly_name": null,
					"labels": null,
					"location": "US",
					"max_time_travel_hours": null,
					"timeouts": null,
				},
				"sensitive_values": {
					"access": [],
					"default_encryption_configuration": [],
				},
			},
			{
				"address": "google_bigquery_dataset_access.access",
				"mode": "managed",
				"type": "google_bigquery_dataset_access",
				"name": "access",
				"provider_name": "registry.terraform.io/hashicorp/google",
				"schema_version": 0,
				"values": {
					"dataset": [],
					"dataset_id": "dataset_with_access",
					"domain": null,
					"group_by_email": null,
					"iam_member": null,
					"role": "OWNER",
					"routine": [],
					"special_group": access_config,
					"timeouts": null,
					"user_by_email": null,
					"view": [],
				},
				"sensitive_values": {
					"dataset": [],
					"routine": [],
					"view": [],
				},
			},
		]}},
		"resource_changes": [
			{
				"address": "google_bigquery_dataset.dataset_with_access",
				"mode": "managed",
				"type": "google_bigquery_dataset",
				"name": "dataset_with_access",
				"provider_name": "registry.terraform.io/hashicorp/google",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"dataset_id": "dataset_with_access",
						"default_encryption_configuration": [],
						"default_partition_expiration_ms": null,
						"default_table_expiration_ms": null,
						"delete_contents_on_destroy": false,
						"description": null,
						"friendly_name": null,
						"labels": null,
						"location": "US",
						"max_time_travel_hours": null,
						"timeouts": null,
					},
					"after_unknown": {
						"access": true,
						"creation_time": true,
						"default_encryption_configuration": [],
						"etag": true,
						"id": true,
						"last_modified_time": true,
						"project": true,
						"self_link": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"access": [],
						"default_encryption_configuration": [],
					},
				},
			},
			{
				"address": "google_bigquery_dataset_access.access",
				"mode": "managed",
				"type": "google_bigquery_dataset_access",
				"name": "access",
				"provider_name": "registry.terraform.io/hashicorp/google",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"dataset": [],
						"dataset_id": "dataset_with_access",
						"domain": null,
						"group_by_email": null,
						"iam_member": null,
						"role": "OWNER",
						"routine": [],
						"special_group": access_config,
						"timeouts": null,
						"user_by_email": null,
						"view": [],
					},
					"after_unknown": {
						"api_updated_member": true,
						"dataset": [],
						"id": true,
						"project": true,
						"routine": [],
						"view": [],
					},
					"before_sensitive": false,
					"after_sensitive": {
						"dataset": [],
						"routine": [],
						"view": [],
					},
				},
			},
		],
		"configuration": {
			"provider_config": {"google": {
				"name": "google",
				"full_name": "registry.terraform.io/hashicorp/google",
				"version_constraint": "~> 4.0",
				"expressions": {
					"project": {"constant_value": "tfc-test-370816"},
					"region": {"constant_value": "us-central1"},
					"zone": {"constant_value": "us-central1-c"},
				},
			}},
			"root_module": {"resources": [
				{
					"address": "google_bigquery_dataset.dataset_with_access",
					"mode": "managed",
					"type": "google_bigquery_dataset",
					"name": "dataset_with_access",
					"provider_config_key": "google",
					"expressions": {"dataset_id": {"constant_value": "dataset_with_access"}},
					"schema_version": 0,
				},
				{
					"address": "google_bigquery_dataset_access.access",
					"mode": "managed",
					"type": "google_bigquery_dataset_access",
					"name": "access",
					"provider_config_key": "google",
					"expressions": {
						"dataset_id": {"references": [
							"google_bigquery_dataset.dataset_with_access.dataset_id",
							"google_bigquery_dataset.dataset_with_access",
						]},
						"role": {"constant_value": "OWNER"},
						"special_group": {"constant_value": access_config},
					},
					"schema_version": 0,
				},
			]},
		},
	}
}
