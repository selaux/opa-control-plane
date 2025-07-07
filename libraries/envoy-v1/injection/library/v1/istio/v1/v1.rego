package library.v1.istio.v1

default uid = "missing-uid"

uid = input.request.uid

inject = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"response": {
		"uid": uid,
		"allowed": true,
		"patchType": "JSONPatch",
		"patch": base64.encode(json.marshal(patch)),
	},
}

patch = [
	{
		"op": "add",
		"path": "/spec/containers/-",
		"value": opa_container,
	},
	{
		"op": "add",
		"path": "/spec/volumes/-",
		"value": opa_config_volume,
	},
]

opa_container = {
	# TODO opa version should be configurable
	"image": "openpolicyagent/opa:1.5.1-envoy",
	"name": "opa-istio",
	"args": [
		"run",
		"--server",
		"--config-file=/config/conf.yaml",
	],
	"volumeMounts": [{
		"mountPath": "/config",
		"name": "opa-config",
	}],
	"readinessProbe": {"httpGet": {
		"path": "/health?bundles",
		"port": 8181,
	}},
}

opa_config_volume = {
	"name": "opa-config",
	"configMap": {"name": "opa-istio-das-config"},
}
