package global.systemtypes["terraform:2.0"].library.provider.gcp.compute.serviceaccount.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.compute.serviceaccount.v1 as serviceaccount

############################
# unit tests
test_prohibit_default_service_account_good {
	service_account_config = [{"email": "dummy_email@customdeveloper.customserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]
	in = input_with_google_compute_instance_resource(service_account_config)
	actual := serviceaccount.prohibit_default_service_account with input as in
	count(actual) == 0
}

test_prohibit_default_service_account_bad_using_defaults {
	service_account_config = [{"email": "dummy_email@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]
	in = input_with_google_compute_instance_resource(service_account_config)
	actual := serviceaccount.prohibit_default_service_account with input as in
	count(actual) == 1
}

test_prohibit_default_service_account_bad_missing_email {
	service_account_config = [{"scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]
	in = input_with_google_compute_instance_resource(service_account_config)
	actual := serviceaccount.prohibit_default_service_account with input as in
	count(actual) == 1
}

test_prohibit_default_service_account_bad_empty_service_account {
	service_account_config = []
	in = input_with_google_compute_instance_resource(service_account_config)
	actual := serviceaccount.prohibit_default_service_account with input as in
	count(actual) == 1
}

#################
# test input data
input_with_google_compute_instance_resource(service_account_config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.8",
		"planned_values": {"root_module": {"resources": [{
			"address": "google_compute_instance.default",
			"mode": "managed",
			"type": "google_compute_instance",
			"name": "default",
			"provider_name": "registry.terraform.io/hashicorp/google",
			"schema_version": 6,
			"values": {
				"allow_stopping_for_update": null,
				"attached_disk": [],
				"boot_disk": [{
					"auto_delete": true,
					"disk_encryption_key_raw": null,
					"initialize_params": [{"image": "debian-cloud/debian-9"}],
					"mode": "READ_WRITE",
				}],
				"can_ip_forward": false,
				"deletion_protection": false,
				"description": null,
				"desired_status": null,
				"enable_display": null,
				"hostname": null,
				"labels": null,
				"machine_type": "e2-medium",
				"metadata": null,
				"metadata_startup_script": null,
				"name": "test",
				"network_interface": [{
					"access_config": [],
					"alias_ip_range": [],
					"network": "default",
					"nic_type": null,
				}],
				"resource_policies": null,
				"scratch_disk": [{"interface": "SCSI"}],
				"service_account": service_account_config,
				"shielded_instance_config": [],
				"tags": [
					"bar",
					"foo",
				],
				"timeouts": null,
				"zone": "us-central1-a",
			},
		}]}},
		"resource_changes": [{
			"address": "google_compute_instance.default",
			"mode": "managed",
			"type": "google_compute_instance",
			"name": "default",
			"provider_name": "registry.terraform.io/hashicorp/google",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allow_stopping_for_update": null,
					"attached_disk": [],
					"boot_disk": [{
						"auto_delete": true,
						"disk_encryption_key_raw": null,
						"initialize_params": [{"image": "debian-cloud/debian-9"}],
						"mode": "READ_WRITE",
					}],
					"can_ip_forward": false,
					"deletion_protection": false,
					"description": null,
					"desired_status": null,
					"enable_display": null,
					"hostname": null,
					"labels": null,
					"machine_type": "e2-medium",
					"metadata": null,
					"metadata_startup_script": null,
					"name": "test",
					"network_interface": [{
						"access_config": [],
						"alias_ip_range": [],
						"network": "default",
						"nic_type": null,
					}],
					"resource_policies": null,
					"scratch_disk": [{"interface": "SCSI"}],
					"service_account": service_account_config,
					"shielded_instance_config": [],
					"tags": [
						"bar",
						"foo",
					],
					"timeouts": null,
					"zone": "us-central1-a",
				},
				"after_unknown": {
					"attached_disk": [],
					"boot_disk": [{
						"device_name": true,
						"disk_encryption_key_sha256": true,
						"initialize_params": [{
							"labels": true,
							"size": true,
							"type": true,
						}],
						"kms_key_self_link": true,
						"source": true,
					}],
					"confidential_instance_config": true,
					"cpu_platform": true,
					"current_status": true,
					"guest_accelerator": true,
					"id": true,
					"instance_id": true,
					"label_fingerprint": true,
					"metadata_fingerprint": true,
					"min_cpu_platform": true,
					"network_interface": [{
						"access_config": [],
						"alias_ip_range": [],
						"name": true,
						"network_ip": true,
						"subnetwork": true,
						"subnetwork_project": true,
					}],
					"project": true,
					"scheduling": true,
					"scratch_disk": [{}],
					"self_link": true,
					"service_account": [{"scopes": [false]}],
					"shielded_instance_config": [],
					"tags": [
						false,
						false,
					],
					"tags_fingerprint": true,
				},
			},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "google_compute_instance.default",
			"mode": "managed",
			"type": "google_compute_instance",
			"name": "default",
			"provider_config_key": "google",
			"expressions": {
				"boot_disk": [{"initialize_params": [{"image": {"constant_value": "debian-cloud/debian-9"}}]}],
				"machine_type": {"constant_value": "e2-medium"},
				"name": {"constant_value": "test"},
				"network_interface": [{"network": {"constant_value": "default"}}],
				"scratch_disk": [{"interface": {"constant_value": "SCSI"}}],
				"service_account": [{
					"email": {"constant_value": "dummy_email@developer.gserviceaccount.com"},
					"scopes": {"constant_value": ["cloud-platform"]},
				}],
				"tags": {"constant_value": [
					"foo",
					"bar",
				]},
				"zone": {"constant_value": "us-central1-a"},
			},
			"schema_version": 6,
		}]}},
	}
}
