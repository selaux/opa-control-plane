package library.v1.kubernetes.utils.envoy.test_v1

import data.library.v1.kubernetes.utils.envoy.v1 as envoy_utils
import data.library.v1.kubernetes.utils.opa.v1 as opa_utils

# ------------------------------------------------------------------------------
# test init_patch and related checks

test_init_patch {
	expected_init_seting := true
	expected_path := "test"

	append := envoy_utils.init_patch with envoy_utils.init_containers as true
		with opa_utils.root_path as expected_path
		with envoy_utils.init_container_patch as expected_init_seting

	append.path == sprintf("%v/spec/initContainers/-", [expected_path])
	sprintf("%s", [append.value]) == sprintf("%s", [expected_init_seting])

	new_container := envoy_utils.init_patch with envoy_utils.init_containers as false
		with opa_utils.root_path as expected_path
		with envoy_utils.init_container_patch as expected_init_seting

	new_container.path == sprintf("%v/spec/initContainers", [expected_path])
	expected_init_seting == new_container.value[_]
}

test_init_image {
	expected_rapid_init_image := "rapid"

	expected_regular_init_image := "regular"

	expected_stable_init_image := "stable"

	policy := {"com.styra.kubernetes.mutating": {"rules": {"rules": {
		"rapid_channel_init_image": expected_rapid_init_image,
		"regular_channel_init_image": expected_regular_init_image,
		"stable_channel_init_image": expected_stable_init_image,
	}}}}

	rapid := envoy_utils.init_image with data.library.parameters.channel as "Rapid" with data.policy as policy
	rapid == expected_rapid_init_image
	regular := envoy_utils.init_image with data.library.parameters.channel as "Regular" with data.policy as policy
	regular == expected_regular_init_image
	stable := envoy_utils.init_image with data.library.parameters.channel as "Stable" with data.policy as policy
	stable == expected_stable_init_image
}

# ------------------------------------------------------------------------------
# test envoy_patch and related checks

test_envoy_image {
	expected_rapid_envoy_image := "rapid"

	expected_regular_envoy_image := "regular"

	expected_stable_envoy_image := "stable"

	policy := {"com.styra.kubernetes.mutating": {"rules": {"rules": {
		"rapid_channel_envoy_image": expected_rapid_envoy_image,
		"regular_channel_envoy_image": expected_regular_envoy_image,
		"stable_channel_envoy_image": expected_stable_envoy_image,
	}}}}

	rapid := envoy_utils.envoy_image with data.library.parameters.channel as "Rapid" with data.policy as policy
	rapid == expected_rapid_envoy_image
	regular := envoy_utils.envoy_image with data.library.parameters.channel as "Regular" with data.policy as policy
	regular == expected_regular_envoy_image
	stable := envoy_utils.envoy_image with data.library.parameters.channel as "Stable" with data.policy as policy
	stable == expected_stable_envoy_image
}

# ------------------------------------------------------------------------------
# test opa_and_envoy_volume_patch and related checks

test_opa_and_envoy_volume_patch {
	expected_root_path := "test"
	expected_opa_volume := "opa_test"
	expected_envoy_volume := "envoy_test"
	expected_socket_volume := "socket_test"

	append_volume_patch := envoy_utils.opa_and_envoy_volume_patch with opa_utils.existing_volumes as true
		with opa_utils.root_path as expected_root_path
		with opa_utils.opa_volume as expected_opa_volume
		with envoy_utils.envoy_volume as expected_envoy_volume
		with envoy_utils.socket_volume as expected_socket_volume

	sprintf("%s", [append_volume_patch[0].value]) == expected_opa_volume
	sprintf("%s", [append_volume_patch[1].value]) == expected_envoy_volume
	sprintf("%s", [append_volume_patch[2].value]) == expected_socket_volume
	p := append_volume_patch[_]
	p.path == sprintf("%v/spec/volumes/-", [expected_root_path])

	new_volume_patch := envoy_utils.opa_and_envoy_volume_patch with opa_utils.existing_volumes as false
		with opa_utils.root_path as expected_root_path
		with opa_utils.opa_volume as expected_opa_volume
		with envoy_utils.envoy_volume as expected_envoy_volume
		with envoy_utils.socket_volume as expected_socket_volume

	new_volume_patch[0].path == sprintf("%v/spec/volumes", [expected_root_path])
	expected_opa_volume == new_volume_patch[0].value[_]
	expected_envoy_volume == new_volume_patch[0].value[_]
	expected_socket_volume == new_volume_patch[0].value[_]
}
