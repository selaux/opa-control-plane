package global.systemtypes["terraform:2.0"].library.provider.gcp.storage.versioning.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.storage.versioning.v1 as versioning

test_prohibit_bucket_without_versioning_good {
	versioning_config := [{"enabled": true}]
	inp := input_with_google_storage_bucket_resource(versioning_config)
	actual := versioning.prohibit_bucket_without_versioning with input as inp
	count(actual) == 0
}

test_prohibit_bucket_without_versioning_bad_missing {
	inp := json.remove(
		input_with_google_storage_bucket_resource(["deleteme"]),
		[
			"planned_values/root_module/resources/0/values/versioning",
			"resource_changes/0/change/after/versioning",
		],
	)
	actual := versioning.prohibit_bucket_without_versioning with input as inp
	count(actual) == 1
}

test_prohibit_bucket_without_versioning_bad_empty {
	versioning_config := []
	inp := input_with_google_storage_bucket_resource(versioning_config)
	actual := versioning.prohibit_bucket_without_versioning with input as inp
	count(actual) == 1
}

test_prohibit_bucket_without_versioning_bad_not_enabled {
	versioning_config := [{"enabled": false}]
	inp := input_with_google_storage_bucket_resource(versioning_config)
	actual := versioning.prohibit_bucket_without_versioning with input as inp
	count(actual) == 1
}

#################
# test input data
input_with_google_storage_bucket_resource(versioning_config) := {
	"format_version": "0.1",
	"terraform_version": "0.12.15",
	"planned_values": {"root_module": {"resources": [{
		"address": "google_storage_bucket.static-site",
		"mode": "managed",
		"type": "google_storage_bucket",
		"name": "static-site",
		"provider_name": "google",
		"schema_version": 0,
		"values": {
			"cors": [{
				"max_age_seconds": 3600,
				"method": [
					"GET",
					"HEAD",
					"PUT",
					"POST",
					"DELETE",
				],
				"origin": ["http://image-store.com"],
				"response_header": ["*"],
			}],
			"default_event_based_hold": null,
			"encryption": [],
			"force_destroy": true,
			"labels": null,
			"lifecycle_rule": [],
			"location": "EU",
			"logging": [],
			"name": "image-store.com",
			"requester_pays": null,
			"retention_policy": [],
			"storage_class": "STANDARD",
			"uniform_bucket_level_access": true,
			"versioning": versioning_config,
			"website": [{
				"main_page_suffix": "index.html",
				"not_found_page": "404.html",
			}],
		},
	}]}},
	"resource_changes": [{
		"address": "google_storage_bucket.static-site",
		"mode": "managed",
		"type": "google_storage_bucket",
		"name": "static-site",
		"provider_name": "google",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"cors": [{
					"max_age_seconds": 3600,
					"method": [
						"GET",
						"HEAD",
						"PUT",
						"POST",
						"DELETE",
					],
					"origin": ["http://image-store.com"],
					"response_header": ["*"],
				}],
				"default_event_based_hold": null,
				"encryption": [],
				"force_destroy": true,
				"labels": null,
				"lifecycle_rule": [],
				"location": "EU",
				"logging": [],
				"name": "image-store.com",
				"requester_pays": null,
				"retention_policy": [],
				"storage_class": "STANDARD",
				"uniform_bucket_level_access": true,
				"versioning": versioning_config,
				"website": [{
					"main_page_suffix": "index.html",
					"not_found_page": "404.html",
				}],
			},
			"after_unknown": {
				"bucket_policy_only": true,
				"cors": [{
					"method": [
						false,
						false,
						false,
						false,
						false,
					],
					"origin": [false],
					"response_header": [false],
				}],
				"encryption": [],
				"id": true,
				"lifecycle_rule": [],
				"logging": [],
				"project": true,
				"retention_policy": [],
				"self_link": true,
				"url": true,
				"versioning": [{}],
				"website": [{}],
			},
		},
	}],
	"configuration": {"root_module": {"resources": [{
		"address": "google_storage_bucket.static-site",
		"mode": "managed",
		"type": "google_storage_bucket",
		"name": "static-site",
		"provider_config_key": "google",
		"expressions": {
			"cors": [{
				"max_age_seconds": {"constant_value": 3600},
				"method": {"constant_value": [
					"GET",
					"HEAD",
					"PUT",
					"POST",
					"DELETE",
				]},
				"origin": {"constant_value": ["http://image-store.com"]},
				"response_header": {"constant_value": ["*"]},
			}],
			"force_destroy": {"constant_value": true},
			"location": {"constant_value": "EU"},
			"name": {"constant_value": "image-store.com"},
			"uniform_bucket_level_access": {"constant_value": true},
			"versioning": [{"enabled": {"constant_value": false}}],
			"website": [{
				"main_page_suffix": {"constant_value": "index.html"},
				"not_found_page": {"constant_value": "404.html"},
			}],
		},
		"schema_version": 0,
	}]}},
}
