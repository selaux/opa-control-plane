package global.systemtypes["terraform:2.0"].library.provider.gcp.util.v1

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# Helper rules related to GCP (provider)

# Get GCP compute instance resource changes
compute_instance_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_compute_instance"
}

# Get GCP storage bucket resource changes
storage_bucket_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_storage_bucket"
}

# Get GCP bigquery dataset resource changes
bigquery_dataset_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_bigquery_dataset"
}

# Get GCP bigquery dataset resource changes
bigquery_dataset_access_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_bigquery_dataset_access"
}

# Get GCP IAM member resource changes
project_iam_member_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_project_iam_member"
}

# Get GCP compute firewall resource changes
compute_firewall_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "google_compute_firewall"
}

# Check if 0.0.0.0/0 network
is_zero_network("0.0.0.0/0")

is_zero_network("::/0")

# Check if firewall direction is for ingress
# If direction not set, default is ingress
is_ingress(network) {
	not network.direction
}

is_ingress(network) {
	network.direction == "INGRESS"
}

# Check if restricted port is part of ports in GCP firewall resource
port_range_consists_port(port, restricted_port) {
	not contains(port, "-")
	to_number(port) == to_number(restricted_port)
}

port_range_consists_port(port, restricted_port) {
	contains(port, "-")
	port_range := split(port, "-")
	to_number(port_range[0]) <= to_number(restricted_port)
	to_number(port_range[1]) >= to_number(restricted_port)
}
