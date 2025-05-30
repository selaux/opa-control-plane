package global.systemtypes["terraform:2.0"].library.provider.gcp.network.firewall.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.network.firewall.v1 as firewall

############################
# unit tests
test_prohibit_firewall_with_internet_access_good {
	ports = ["80", "1000-2000"]
	source_ranges = ["1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "INGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 0
}

test_prohibit_firewall_with_internet_access_good_with_ssh_port {
	ports = ["22", "1000-2000"]
	source_ranges = ["1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "INGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 0
}

test_prohibit_firewall_with_internet_access_good_port_with_default_network {
	ports = ["80", "1000-2000"]
	source_ranges = ["0.0.0.0/0", "1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "INGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 0
}

test_prohibit_firewall_with_internet_access_good_egress_traffic {
	ports = ["22", "1000-2000"]
	source_ranges = ["0.0.0.0/0", "1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "EGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 0
}

test_prohibit_firewall_with_internet_access_bad {
	ports = ["22", "1000-2000"]
	source_ranges = ["0.0.0.0/0", "1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "INGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 1
}

test_prohibit_firewall_with_internet_access_bad_port_range {
	ports = ["20-28", "1000-2000", "80"]
	source_ranges = ["0.0.0.0/0", "1.2.3.4/24"]
	in = input_with_google_compute_firewall_resource(ports, source_ranges, "INGRESS")
	actual := firewall.prohibit_firewall_with_internet_access with input as in
	count(actual) == 1
}

#################
# test input data
input_with_google_compute_firewall_resource(ports, source_ranges, direction) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.15",
		"planned_values": {"root_module": {"resources": [{
			"address": "google_compute_firewall.default",
			"mode": "managed",
			"type": "google_compute_firewall",
			"name": "default",
			"provider_name": "google",
			"schema_version": 1,
			"values": {
				"allow": [
					{
						"ports": ports,
						"protocol": "tcp",
					},
					{
						"ports": [],
						"protocol": "icmp",
					},
				],
				"deny": [],
				"description": null,
				"direction": direction,
				"disabled": null,
				"log_config": [],
				"name": "test-firewall",
				"network": "test-network",
				"priority": 1000,
				"source_ranges": source_ranges,
				"source_service_accounts": null,
				"source_tags": null,
				"target_service_accounts": null,
				"target_tags": null,
				"timeouts": null,
			},
		}]}},
		"resource_changes": [{
			"address": "google_compute_firewall.default",
			"mode": "managed",
			"type": "google_compute_firewall",
			"name": "default",
			"provider_name": "google",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allow": [
						{
							"ports": ports,
							"protocol": "tcp",
						},
						{
							"ports": [],
							"protocol": "icmp",
						},
					],
					"deny": [],
					"description": null,
					"direction": direction,
					"disabled": null,
					"log_config": [],
					"name": "test-firewall",
					"network": "test-network",
					"priority": 1000,
					"source_ranges": source_ranges,
					"source_service_accounts": null,
					"source_tags": null,
					"target_service_accounts": null,
					"target_tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"allow": [
						{"ports": [
							false,
							false,
							false,
							false,
						]},
						{"ports": []},
					],
					"creation_timestamp": true,
					"deny": [],
					"destination_ranges": true,
					"enable_logging": true,
					"id": true,
					"log_config": [],
					"project": true,
					"self_link": true,
					"source_ranges": [false],
				},
			},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "google_compute_firewall.default",
			"mode": "managed",
			"type": "google_compute_firewall",
			"name": "default",
			"provider_config_key": "google",
			"expressions": {
				"allow": [
					{"protocol": {"constant_value": "icmp"}},
					{
						"ports": {"constant_value": [
							"80",
							"8080",
							"1000-2000",
							"22",
						]},
						"protocol": {"constant_value": "tcp"},
					},
				],
				"direction": {"constant_value": "INGRESS"},
				"name": {"constant_value": "test-firewall"},
				"network": {"constant_value": "test-network"},
				"source_ranges": {"constant_value": ["0.0.0.0/0"]},
			},
			"schema_version": 1,
		}]}},
	}
}
