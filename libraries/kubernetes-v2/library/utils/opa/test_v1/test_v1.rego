package library.v1.kubernetes.utils.opa.test_v1

import data.library.v1.kubernetes.utils.opa.v1 as opa_utils

# ------------------------------------------------------------------------------
# test injectable_object and related checks

test_injectable_object {
	opa_utils.injectable_object with opa_utils.injectable_pod as true
}

test_injectable_pod {
	operations := ["CREATE", "UPDATE"]

	op := operations[_]
	opa_utils.injectable_pod with input.request.kind.kind as "Pod"
		with input.request.object.metadata.labels.app as ""
		with opa_utils.inject_label as true
		with input.request.operation as op
		with opa_utils.opa_container_exists as false
}

test_inject_label {
	expected_label_name := "name"

	expected_label_value := "value"

	expected_namespace := "test_namespace"

	namespaces := {expected_namespace: {"metadata": {"labels": {expected_label_name: expected_label_value}}}}

	parameters := {
		"label": expected_label_name,
		"label-value": expected_label_value,
	}

	opa_utils.inject_label with data.kubernetes.resources.namespaces as namespaces
		with input.request.namespace as expected_namespace
		with data.library.parameters as parameters

	opa_utils.inject_label with input.request.object.metadata.labels as {expected_label_name: expected_label_value}
		with data.library.parameters as parameters
}

test_opa_container_exists {
	opa_utils.opa_container_exists with input.request.object.spec.containers as [{"name": "opa"}]
}

# ------------------------------------------------------------------------------
# test opa_patch and related checks

test_root_path {
	pod_root := opa_utils.opa_patch with opa_utils.injectable_pod as true
	pod_root.path == "/spec/containers/-"
}

test_opa_image {
	expected_rapid_opa_image := "rapid"

	expected_regular_opa_image := "regular"

	expected_stable_opa_image := "stable"

	policy := {"com.styra.kubernetes.mutating": {"rules": {"rules": {
		"rapid_channel_opa_image": expected_rapid_opa_image,
		"regular_channel_opa_image": expected_regular_opa_image,
		"stable_channel_opa_image": expected_stable_opa_image,
	}}}}

	rapid := opa_utils.opa_image with data.library.parameters.channel as "Rapid" with data.policy as policy
	rapid == expected_rapid_opa_image
	regular := opa_utils.opa_image with data.library.parameters.channel as "Regular" with data.policy as policy
	regular == expected_regular_opa_image
	stable := opa_utils.opa_image with data.library.parameters.channel as "Stable" with data.policy as policy
	stable == expected_stable_opa_image
}

test_opa_volume_mounts {
	no_socket := opa_utils.opa_volume_mounts with data.library.parameters["use-socket"] as "No"
	no_socket == [opa_utils.opa_config_mount]

	socket := opa_utils.opa_volume_mounts with data.library.parameters["use-socket"] as "Yes"
	socket == [opa_utils.opa_config_mount, opa_utils.opa_socket_mount]
}

# ------------------------------------------------------------------------------
# test opa_volume_patch and related checks

test_opa_volume_patch {
	expected_root_path := "test"
	expected_opa_volume := "test"

	append_volume_patch := opa_utils.opa_volume_patch with opa_utils.existing_volumes as true
		with opa_utils.root_path as expected_root_path
		with opa_utils.opa_volume as expected_opa_volume

	append_volume_patch.path == sprintf("%v/spec/volumes/-", [expected_root_path])
	sprintf("%s", [append_volume_patch.value]) == expected_opa_volume

	new_volume_patch := opa_utils.opa_volume_patch with opa_utils.existing_volumes as false
		with opa_utils.root_path as expected_root_path
		with opa_utils.opa_volume as expected_opa_volume

	new_volume_patch.path == sprintf("%v/spec/volumes", [expected_root_path])
	expected_opa_volume == new_volume_patch.value[_]
}

test_existing_volumes {
	opa_utils.existing_volumes with input.request.object.spec.volumes as true
}
