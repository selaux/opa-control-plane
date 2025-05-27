package library.v1.kubernetes.utils.envoy.v1

import data.library.v1.kubernetes.utils.opa.v1 as opa_utils

# ------------------------------------------------------------------------------
# init_patch adds the proxy-init container to redirect traffic to Envoy sidecar

init_patch = patch {
	init_containers
	patch := {
		"op": "add",
		"path": sprintf("%v/spec/initContainers/-", [opa_utils.root_path]),
		"value": init_container_patch,
	}
}

init_patch = patch {
	not init_containers
	patch = {
		"op": "add",
		"path": sprintf("%v/spec/initContainers", [opa_utils.root_path]),
		"value": [init_container_patch],
	}
}

init_containers {
	input.request.object.spec.initContainers
}

init_container_patch := {
	"image": init_image,
	"name": "proxy-init",
	"args": [
		"-p",
		"8000",
		"-o",
		"8001",
		"-u",
		"1111",
		"-w",
		"8282",
	],
	"securityContext": {
		"capabilities": {"add": ["NET_ADMIN"]},
		"runAsNonRoot": false,
		"runAsUser": 0,
	},
}

default init_image := "openpolicyagent/proxy_init:latest"

init_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.rapid_channel_init_image {
	data.library.parameters.channel == "Rapid"
}

init_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.regular_channel_init_image {
	data.library.parameters.channel == "Regular"
}

init_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.stable_channel_init_image {
	data.library.parameters.channel == "Stable"
}

# ------------------------------------------------------------------------------
# envoy_patch adds an enovy sidecar

envoy_patch := {
	"op": "add",
	"path": sprintf("%v/spec/containers/-", [opa_utils.root_path]),
	"value": {
		"name": "envoy",
		"image": envoy_image,
		"volumeMounts": [
			{
				"readOnly": true,
				"mountPath": "/config",
				"name": "envoy-config-vol",
			},
			{
				"readOnly": false,
				"mountPath": "/run/opa/sockets",
				"name": "opa-socket",
			},
		],
		"args": [
			"envoy",
			"--config-path",
			"/config/envoy.yaml",
		],
		"env": [{
			"name": "ENVOY_UID",
			"value": "1111",
		}],
	},
}

# Envoy doesn't tag a "lastest" version, either way this should be
# matched with the configuration of DAS
default envoy_image := "envoyproxy/envoy:v1.21-latest"

envoy_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.rapid_channel_envoy_image {
	data.library.parameters.channel == "Rapid"
}

envoy_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.regular_channel_envoy_image {
	data.library.parameters.channel == "Regular"
}

envoy_image := data.policy["com.styra.kubernetes.mutating"].rules.rules.stable_channel_envoy_image {
	data.library.parameters.channel == "Stable"
}

# ------------------------------------------------------------------------------
# opa_and_envoy_volume_patch adds a new volume for opa and envoy

opa_and_envoy_volume_patch := patch {
	opa_utils.existing_volumes
	patch := [
		{
			"op": "add",
			"path": sprintf("%v/spec/volumes/-", [opa_utils.root_path]),
			"value": opa_utils.opa_volume,
		},
		{
			"op": "add",
			"path": sprintf("%v/spec/volumes/-", [opa_utils.root_path]),
			"value": envoy_volume,
		},
		{
			"op": "add",
			"path": sprintf("%v/spec/volumes/-", [opa_utils.root_path]),
			"value": socket_volume,
		},
	]
}

opa_and_envoy_volume_patch := patch {
	not opa_utils.existing_volumes
	patch := [{
		"op": "add",
		"path": sprintf("%v/spec/volumes", [opa_utils.root_path]),
		"value": [opa_utils.opa_volume, envoy_volume, socket_volume],
	}]
}

envoy_volume := {
	"name": "envoy-config-vol",
	"configMap": {"name": data.library.parameters["config-envoy"]},
}

socket_volume := {
	"name": "opa-socket",
	"emptyDir": {},
}
