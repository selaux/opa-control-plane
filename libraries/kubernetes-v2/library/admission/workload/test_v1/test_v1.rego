package library.v1.kubernetes.admission.workload.test_v1

import data.library.v1.kubernetes.admission.workload.v1

test_repository_parse {
	# with tag
	v1.parse_image("foo/bar:0.2") == {"host": "", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": null}

	v1.parse_image("localhost/foo/bar:0.2") == {"host": "localhost", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": null}

	v1.parse_image("localhost:8181/foo/bar:0.2") == {"host": "localhost", "port": 8181, "repo": "foo/bar", "tag": "0.2", "digest": null}

	v1.parse_image("acme.com:8181/foo/bar:0.2") == {"host": "acme.com", "port": 8181, "repo": "foo/bar", "tag": "0.2", "digest": null}

	v1.parse_image("acme.com/foo/bar:0.2") == {"host": "acme.com", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": null}

	# without tag
	v1.parse_image("foo/bar") == {"host": "", "port": null, "repo": "foo/bar", "tag": null, "digest": null}

	v1.parse_image("foo") == {"host": "", "port": null, "repo": "foo", "tag": null, "digest": null}

	v1.parse_image("localhost/foo/bar") == {"host": "localhost", "port": null, "repo": "foo/bar", "tag": null, "digest": null}

	v1.parse_image("localhost:8181/foo/bar") == {"host": "localhost", "port": 8181, "repo": "foo/bar", "tag": null, "digest": null}

	v1.parse_image("acme.com:8181/foo/bar") == {"host": "acme.com", "port": 8181, "repo": "foo/bar", "tag": null, "digest": null}

	v1.parse_image("acme.com/foo/bar") == {"host": "acme.com", "port": null, "repo": "foo/bar", "tag": null, "digest": null}

	# with digest
	v1.parse_image("foo/bar:0.2@123456abc:713") == {"host": "", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": "123456abc:713"}

	v1.parse_image("localhost/foo/bar:0.2@123456abc:713") == {"host": "localhost", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": "123456abc:713"}

	v1.parse_image("localhost:8181/foo/bar:0.2@123456abc:713") == {"host": "localhost", "port": 8181, "repo": "foo/bar", "tag": "0.2", "digest": "123456abc:713"}

	v1.parse_image("acme.com:8181/foo/bar:0.2@123456abc:713") == {"host": "acme.com", "port": 8181, "repo": "foo/bar", "tag": "0.2", "digest": "123456abc:713"}

	v1.parse_image("acme.com/foo/bar:0.2@123456abc:713") == {"host": "acme.com", "port": null, "repo": "foo/bar", "tag": "0.2", "digest": "123456abc:713"}

	# extras
	v1.parse_image("finance.acme.com/foo/bar") == {"host": "finance.acme.com", "port": null, "repo": "foo/bar", "tag": null, "digest": null}

	v1.parse_image("finance.acme.com/foo/bar:0.2.33.2..34") == {"host": "finance.acme.com", "port": null, "repo": "foo/bar", "tag": "0.2.33.2..34", "digest": null}

	v1.parse_image("finance.acme.com/heapster-v1.6.0-beta.1-8c76f98c7-g4xdh:0.2.33.2..34") == {"host": "finance.acme.com", "port": null, "repo": "heapster-v1.6.0-beta.1-8c76f98c7-g4xdh", "tag": "0.2.33.2..34", "digest": null}

	v1.parse_image("hooli.com/nginx") == {"host": "hooli.com", "port": null, "repo": "nginx", "tag": null, "digest": null}
}

test_k8s_deny_configmap_items_in_blacklist_ok {
	in := input_pod_with_items("test")
	p := {"prohibited_keys": {"password"}}
	actual := v1.deny_configmap_items_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_deny_configmap_items_in_blacklist_fail {
	in := input_pod_with_items("test")
	p := {"prohibited_keys": {"test"}}
	actual := v1.deny_configmap_items_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

input_pod_with_items(key) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "dapi-test-pod"},
				"spec": {
					"containers": [{
						"name": "test-container",
						"image": "k8s.gcr.io/busybox",
						"command": [
							"/bin/sh",
							"-c",
							"cat /etc/config/keys",
						],
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": [{
						"name": "config-volume",
						"configMap": {
							"name": "special-config",
							"items": [{
								"key": key,
								"path": "keys",
							}],
						},
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}
}

test_k8s_deny_host_network_fail {
	x := input_readiness_only
	actual := v1.deny_host_network with input as x

	count(actual) == 1
}

test_k8s_deny_host_network_ok {
	x := input_liveness_only
	actual := v1.deny_host_network with input as x

	count(actual) == 0
}

test_k8s_deny_host_paths_ok {
	in := input_pod_host_path
	p := {"prohibited_host_paths": {"/proc"}}
	actual := v1.deny_host_path_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_host_paths_ok_no_parameter {
	in := input_pod_host_path
	actual := v1.deny_host_path_in_blacklist with input as in
	count(actual) == 0
}

test_k8s_deny_host_paths_fail {
	in := input_pod_host_path
	p := {"prohibited_host_paths": {"/data*"}}
	actual := v1.deny_host_path_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_pod_host_path = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "prod",
		"object": {
			"metadata": {"name": "test-pd"},
			"spec": {
				"containers": [{
					"image": "k8s.gcr.io/test-webserver",
					"name": "test-container",
					"volumeMounts": [{
						"mountPath": "/test-pd",
						"name": "test-volume",
					}],
				}],
				"volumes": [{
					"name": "test-volume",
					"hostPath": {
						"path": "/data",
						"type": "Directory",
					},
				}],
			},
		},
	},
}

input_pod_host_path_with_ephemeral_container = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "prod",
		"object": {
			"metadata": {"name": "test-pd"},
			"spec": {
				"containers": [{
					"image": "k8s.gcr.io/test-webserver",
					"name": "test-container",
					"volumeMounts": [{
						"mountPath": "/test-pd",
						"name": "test-volume",
					}],
				}],
				"ephemeralContainers": [{
					"image": "k8s.gcr.io/test-ephemeral",
					"imagePullPolicy": "IfNotPresent",
					"name": "debugger-2w64s",
					"resources": {},
					"stdin": true,
					"targetContainerName": "test-container",
					"terminationMessagePath": "/dev/termination-log",
					"terminationMessagePolicy": "File",
					"tty": true,
				}],
				"volumes": [{
					"name": "test-volume",
					"hostPath": {
						"path": "/data",
						"type": "Directory",
					},
				}],
			},
		},
	},
}

###################
# Repository safety

test_k8s_repository_unsafe_container_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": set()})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_unsafe_init_container_bad {
	in := input_with_images({"containers": {"hooli.com/busybox"}, "initcontainers": {"nginx"}})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_unsafe_container_good1 {
	in := input_with_images({"containers": {"hooli.com/nginx"}, "initcontainers": set()})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_unsafe_container_good2 {
	in := input_with_images({"containers": {"busybox"}, "initcontainers": set()})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_unsafe_container_good3 {
	in := input_with_images({"containers": {"hooli.com"}, "initcontainers": {"hooli.com/nginx"}})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_unsafe_container_good4 {
	in := input_with_images({"containers": {"hooli.com"}, "initcontainers": {"busybox"}})
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_unsafe_deployment_bad {
	in := input_with_deployment("foo", "foo")
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_unsafe_deployment_good {
	in := input_with_deployment("hooli", "hooli.com/bar")
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_unsafe_replicaset_bad {
	in := input_with_replica_set("foo")
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_unsafe_replicaset_good {
	in := input_with_replica_set("mysql")
	p := {"whitelist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.repository_unsafe_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_all_registries {
	deployment := {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "frontend",
			"namespace": "default",
		},
		"spec": {
			"replicas": 2,
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {},
				"spec": {
					"containers": [{
						"image": "nginx:v1.0.0",
						"name": "nginx",
					}],
					"initContainers": [{
						"image": "hooli.com/opa:latest",
						"name": "opa",
					}],
				},
			},
		},
	}

	res := v1.all_registries with data.kubernetes.resources.deployments["default"].frontend as deployment
	res.whitelist == {"": [], "hooli.com": []}
}

###################
# Repository safety (globs)

test_k8s_repository_glob_exact_match_ok {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": set()})
	p := {"whitelist": {"": {"mysql", "nginx"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_glob_exact_match_ok2 {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"whitelist": {"quay.io": {"org/project"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_glob_exact_match_bad {
	in := input_with_images({"containers": {"foo/nginx"}, "initcontainers": set()})
	p := {"whitelist": {"hub.docker.com": {"mysql", "nginx", "foo"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_glob_one_star_bad {
	in := input_with_images({"containers": {"*/nginx"}, "initcontainers": {"*/postgresql"}})
	p := {"whitelist": {"": {"mysql", "nginx", "foo"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_repository_glob_one_star_bad2 {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"whitelist": {"quay.io": {"*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_glob_one_star_ok {
	in := input_with_images({"containers": {"quay.io/nginx"}, "initcontainers": set()})
	p := {"whitelist": {"quay.io": {"*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_glob_two_stars_ok {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"whitelist": {"quay.io": {"*/*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_glob_org_ok {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"quay.io/org/another-project"}})
	p := {"whitelist": {"quay.io": {"org/*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_repository_glob_two_registries_bad {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"org/another-project"}})
	p := {"whitelist": {"quay.io": {"org/*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_repository_glob_partial_allowed_image_ephemeral {
	p := {"whitelist": {"k8s.gcr.io": {"test-ephemeral"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as input_pod_host_path_with_ephemeral_container

	count(actual) == 1
}

test_k8s_repository_glob_both_allowed_image_ephemeral {
	p := {"whitelist": {"k8s.gcr.io": {"test-*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as input_pod_host_path_with_ephemeral_container

	count(actual) == 0
}

test_k8s_repository_glob_none_allowed_image_ephemeral {
	p := {"whitelist": {"wrong": {"test-*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as input_pod_host_path_with_ephemeral_container

	count(actual) == 2
}

test_k8s_repository_glob_two_registries_ok {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"org/another-project"}})
	p := {"whitelist": {"quay.io": {"org/*"}, "": {"org/*"}}}
	actual := v1.repository_unsafe_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# Repository Saftey Blocklist
test_k8s_block_repository_container_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": set()})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_init_container_bad {
	in := input_with_images({"containers": {"hooli.com/busybox"}, "initcontainers": {"nginx"}})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_container_bad1 {
	in := input_with_images({"containers": {"hooli.com/nginx"}, "initcontainers": set()})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_container_bad2 {
	in := input_with_images({"containers": {"busybox"}, "initcontainers": set()})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_container_bad3 {
	in := input_with_images({"containers": {"hooli.com"}, "initcontainers": {"hooli.com/nginx"}})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_block_repository_container_bad4 {
	in := input_with_images({"containers": {"hooli.com"}, "initcontainers": {"busybox"}})
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_block_repository_deployment_good {
	in := input_with_deployment("foo", "foo")
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_deployment_bad {
	in := input_with_deployment("hooli", "hooli.com/bar")
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_replicaset_bad {
	in := input_with_replica_set("foo")
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_replicaset_good {
	in := input_with_replica_set("mysql")
	p := {"blocklist": {"hooli.com": set(), "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_deployment_good2 {
	in := input_with_deployment("hooli", "hooli.com/bar")
	p := {"blocklist": {"hooli.com": {"foo"}, "": {"mysql", "busybox"}}}
	actual := v1.block_repository_exact with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Repository safety (globs)

test_k8s_block_repository_glob_exact_match_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": set()})
	p := {"blocklist": {"": {"mysql", "nginx"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_glob_exact_match_bad2 {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"blocklist": {"quay.io": {"org/project"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_glob_exact_match_good {
	in := input_with_images({"containers": {"foo/nginx"}, "initcontainers": set()})
	p := {"blocklist": {"hub.docker.com": {"mysql", "nginx", "foo"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_glob_one_star_good {
	in := input_with_images({"containers": {"*/nginx"}, "initcontainers": {"*/postgresql"}})
	p := {"blocklist": {"": {"mysql", "nginx", "foo"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_glob_one_star_good {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"blocklist": {"quay.io": {"*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_block_repository_glob_one_star_bad {
	in := input_with_images({"containers": {"quay.io/nginx"}, "initcontainers": set()})
	p := {"blocklist": {"quay.io": {"*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_glob_two_stars_bad {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": set()})
	p := {"blocklist": {"quay.io": {"*/*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_glob_org_bad {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"quay.io/org/another-project"}})
	p := {"blocklist": {"quay.io": {"org/*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_block_repository_glob_two_registries_bad {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"org/another-project"}})
	p := {"blocklist": {"quay.io": {"org/*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_block_repository_glob_two_registries_bad2 {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"org/another-project"}})
	p := {"blocklist": {"quay.io": {"org/*"}, "": {"org/*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_block_repository_glob_two_registries_good {
	in := input_with_images({"containers": {"quay.io/org/project"}, "initcontainers": {"org/another-project"}})
	p := {"blocklist": {"quay.io": {"foo/*"}, "": {"new/*"}}}
	actual := v1.block_repository_glob with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Latest images

test_k8s_block_latest_image_tag_container_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": set()})
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_container_bad2 {
	in := input_with_images({"containers": {"nginx:latest"}, "initcontainers": set()})
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_init_container_bad {
	in := input_with_images({"containers": {"nginx:v1.0.0"}, "initcontainers": {"nginx"}})
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_init_container_bad2 {
	in := input_with_images({"containers": {"nginx:v1.0.0"}, "initcontainers": {"nginx:latest"}})
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_container_good {
	in := input_with_images({"containers": {"nginx:v1.0.0"}, "initcontainers": set()})
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 0
}

test_k8s_block_latest_image_tag_container_good2 {
	in := input_with_images({
		"containers": {"acme.com:8181/nginx:v1.0.0"},
		"initcontainers": set(),
	})

	actual := v1.block_latest_image_tag with input as in

	count(actual) == 0
}

test_k8s_block_latest_image_tag_deployment_bad {
	in := input_with_deployment("hooli", "hooli.com/bar")
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_deployment_good {
	in := input_with_deployment("hooli", "hooli.com/bar:1.3")
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 0
}

test_k8s_block_latest_image_tag_deployment_bad1 {
	in := input_with_deployment("hooli", "hooli.com/bar:latest")
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_replica_set_bad {
	in := input_with_replica_set("mysql")
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 1
}

test_k8s_block_latest_image_tag_replica_set_good {
	in := input_with_replica_set("mysql:0.1")
	actual := v1.block_latest_image_tag with input as in

	count(actual) == 0
}

# ------------------------------------------------------------------------------
# Missing Resource Requirements

# Any Requirements

test_k8s_expect_container_resource_requirements_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [
					{
						"image": "nginx:v1.0.0",
						"name": "nginx",
					},
					{
						"image": "opa:latest",
						"name": "opa",
					},
				]},
			},
		},
	}

	actual := v1.expect_container_resource_requirements with input as in

	count(actual) == 4
}

test_k8s_expect_container_resource_requirements_good {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {
			"metadata": {"name": "foo"},
			"spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"resources": {
						"requests": {"cpu": "250m"},
						"limits": {"memory": "64Mi"},
					},
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {
						"requests": {"cpu": "250m"},
						"limits": {"memory": "64Mi"},
					},
				}],
			},
		},
	}}

	actual := v1.expect_container_resource_requirements with input as in

	count(actual) == 0
}

# Minimum Requirements

# Cannot be a test_k8s because k8s automatically fills in a request when a
#   limit is provided.
test_k8s_skip_expect_container_resource_requests_bad {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {
			"metadata": {"name": "foo"},
			"spec": {
				"containers": [
					{
						"image": "nginx:v1.0.0",
						"name": "nginx",
					},
					{
						"image": "opa:latest",
						"name": "opa",
						"resources": {"limits": {"memory": "64Mi"}},
					},
				],
				"initContainers": [],
			},
		},
	}}

	actual := v1.expect_container_resource_requests with input as in

	count(actual) == 4
}

test_k8s_expect_container_resource_requests_good {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {
			"metadata": {"name": "foo"},
			"spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"resources": {
						"requests": {
							"cpu": "250m",
							"memory": "64Mi",
						},
						"limits": {"memory": "64Mi"},
					},
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {
						"requests": {
							"cpu": "250m",
							"memory": "64Mi",
						},
						"limits": {"memory": "64Mi"},
					},
				}],
			},
		},
	}}

	actual := v1.expect_container_resource_requests with input as in

	count(actual) == 0
}

# Maximum Requirements

test_k8s_expect_container_resource_limits_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"containers": [{
						"image": "opa:latest",
						"name": "opa",
						"resources": {"requests": {
							"memory": "64Mi",
							"cpu": "250m",
						}},
					}],
					"initContainers": [],
				},
			},
		},
	}

	actual := v1.expect_container_resource_limits with input as in

	count(actual) == 2
}

test_k8s_res_limits_below_low {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"CPULimit": {"low_cpu": "3"}}

	actual := v1.expect_container_resource_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_res_limits_above_high {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"CPULimit": {"high_cpu": "3"}}

	actual := v1.expect_container_resource_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_res_limits_no_parameter1 {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	actual := v1.expect_container_resource_limits with input as in

	count(actual) == 0
}

test_k8s_res_limits_no_parameter {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"CPULimit": {"high_cpu": "3"}}
	actual := v1.expect_container_resource_limits with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_expect_container_resource_limits_good {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"containers": [{
						"image": "nginx:v1.0.0",
						"name": "nginx",
						"resources": {
							"requests": {
								"memory": "64Mi",
								"cpu": "250m",
							},
							"limits": {
								"memory": "64Mi",
								"cpu": "250m",
							},
						},
					}],
					"initContainers": [{
						"image": "opa:latest",
						"name": "opa",
						"resources": {
							"requests": {
								"memory": "64Mi",
								"cpu": "250m",
							},
							"limits": {
								"memory": "64Mi",
								"cpu": "250m",
							},
						},
					}],
				},
			},
		},
	}

	actual := v1.expect_container_resource_limits with input as in

	count(actual) == 0
}

# -------------- ensure_container_resource_limits

test_k8s_ensure_container_cpu_limits_no_limits {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"containers": [{
						"image": "opa:latest",
						"name": "opa",
						"resources": {"requests": {
							"memory": "64Mi",
							"cpu": "250m",
						}},
					}],
					"initContainers": [],
				},
			},
		},
	}

	actual := v1.ensure_container_cpu_limits with input as in

	count(actual) == 1
}

test_k8s_ensure_container_memory_limits_no_limits {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"containers": [{
						"image": "opa:latest",
						"name": "opa",
						"resources": {"requests": {
							"memory": "64Mi",
							"cpu": "250m",
						}},
					}],
					"initContainers": [],
				},
			},
		},
	}

	actual := v1.ensure_container_memory_limits with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_cpu_below_low {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"minimum_cpu_limit": "3"}

	actual := v1.ensure_container_cpu_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_cpu_below_low_unit {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"minimum_cpu_limit": "3000m"}

	actual := v1.ensure_container_cpu_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_cpu_above_high {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"maximum_cpu_limit": "3"}

	actual := v1.ensure_container_cpu_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_cpu_above_high_unit {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"maximum_cpu_limit": "3000m"}

	actual := v1.ensure_container_cpu_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_no_parameter {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	actual := v1.ensure_container_cpu_limits with input as in

	count(actual) == 0
}

test_k8s_ensure_res_limits_memory_below_low {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"minimum_memory_limit": "70Mi"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_memory_below_unit {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "10000Ki",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"minimum_memory_limit": "70Mi"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_memory_below_unit_2 {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "1Ki",
						"cpu": "2",
					}},
				}]},
			},
		},
	}

	p = {"minimum_memory_limit": "10000"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_memory_above_high {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "64Mi",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"maximum_memory_limit": "1000Ki"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_memory_above_high_unit {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "100000000Ki",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"maximum_memory_limit": "1Mi"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_ensure_res_limits_memory_above_high_unit {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "opa:latest",
					"name": "opa",
					"resources": {"limits": {
						"memory": "1Ki",
						"cpu": "8",
					}},
				}]},
			},
		},
	}

	p = {"maximum_memory_limit": "100"}

	actual := v1.ensure_container_memory_limits with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# ------------------------------------------------------------------------------
# Deny Default Namespace

test_k8s_deny_default_namespace_bad_default {
	i := pod_input_with_namespace("default")
	actual := v1.deny_default_namespace with input as i
	count(actual) == 1
}

# Test runner makes sure all namespaces are specified.
# Pending k8s when test runner is fixed.
test_deny_default_namespace_bad_not_specified {
	i := pod_input_with_missing_namespace
	actual := v1.deny_default_namespace with input as i
	count(actual) == 1
}

test_k8s_deny_default_namespace_good {
	i := pod_input_with_namespace("prod")
	actual := v1.deny_default_namespace with input as i
	count(actual) == 0
}

# ------------------------------------------------------------------------------
# Insecure capabilities

test_k8s_deny_capabilities_in_blacklist_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {"metadata": {"namespace": "prod"}, "spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"securityContext": {"capabilities": {
						"add": [
							"NET_ADMIN",
							"SYS_TIME",
						],
						"drop": [
							"NET_ADMIN",
							"SYS_TIME",
							"AUDIT_WRITE",
						],
					}},
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"securityContext": {"capabilities": {"drop": [
						"NET_ADMIN",
						"SYS_TIME",
					]}},
				}],
			}},
		},
	}

	p := {"capabilities": {
		"NET_ADMIN",
		"SYS_TIME",
		"AUDIT_WRITE",
	}}

	actual := v1.deny_capabilities_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_deny_capabilities_in_blacklist_bad_default_capabilities {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {"metadata": {"namespace": "prod"}, "spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"securityContext": {"capabilities": {"add": [
						"NET_ADMIN",
						"SYS_TIME",
					]}},
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"securityContext": {"capabilities": {"drop": [
						"NET_ADMIN",
						"SYS_TIME",
					]}},
				}],
			}},
		},
	}

	p := {"capabilities": {
		"AUDIT_WRITE",
		"SET_GID",
	}}

	actual := v1.deny_capabilities_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_deny_capabilities_in_blacklist_exclude {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {"metadata": {"namespace": "prod"}, "spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"securityContext": {"capabilities": {
						"add": [
							"NET_ADMIN",
							"SYS_TIME",
						],
						"drop": [
							"NET_ADMIN",
							"SYS_TIME",
							"AUDIT_WRITE",
						],
					}},
				}],
				"initContainers": [{
					"image": "e.com/opa:latest",
					"name": "opa",
					"securityContext": {"capabilities": {"drop": [
						"NET_ADMIN",
						"SYS_TIME",
					]}},
				}],
			}},
		},
	}

	p := {
		"capabilities": {
			"NET_ADMIN",
			"SYS_TIME",
			"AUDIT_WRITE",
		},
		"exclude": {"e.com": {"opa"}, "": {"nginx"}},
	}

	actual := v1.deny_capabilities_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_deny_capabilities_in_blacklist_partial_exclude {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {"metadata": {"namespace": "prod"}, "spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"securityContext": {"capabilities": {
						"add": [
							"NET_ADMIN",
							"SYS_TIME",
						],
						"drop": [
							"NET_ADMIN",
							"SYS_TIME",
							"AUDIT_WRITE",
						],
					}},
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"securityContext": {"capabilities": {"drop": [
						"NET_ADMIN",
						"SYS_TIME",
					]}},
				}],
			}},
		},
	}

	p := {
		"capabilities": {
			"NET_ADMIN",
			"SYS_TIME",
			"AUDIT_WRITE",
		},
		"exclude": {"": {"opa"}},
	}

	actual := v1.deny_capabilities_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_deny_capabilities_in_blacklist_good {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {"spec": {
			"containers": [{
				"image": "nginx:v1.0.0",
				"name": "nginx",
				"securityContext": {"capabilities": {
					"add": [
						"AUDIT_READ",
						"NET_BROADCAST",
					],
					"drop": [
						"NET_ADMIN",
						"SYS_TIME",
						"AUDIT_WRITE",
					],
				}},
			}],
			"initContainers": [{
				"image": "opa:latest",
				"name": "opa",
				"securityContext": {"capabilities": {"drop": [
					"NET_ADMIN",
					"SYS_TIME",
					"AUDIT_WRITE",
				]}},
			}],
		}},
	}}

	p := {"capabilities": {
		"NET_ADMIN",
		"SYS_TIME",
		"AUDIT_WRITE",
		"SYS_RAWIO",
	}}

	actual := v1.deny_capabilities_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Host paths

test_k8s_deny_host_path_not_in_whitelist_no_host_path_volume {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {"spec": {
			"containers": [{
				"image": "nginx:v1.0.0",
				"name": "nginx",
				"volumeMounts": [{
					"mountPath": "/test-pd",
					"name": "test-volume",
				}],
			}],
			"volumes": [{
				"name": "test-volume",
				"configMap": {
					"name": "log-config",
					"items": [{
						"key": "log_level",
						"path": "log_level",
					}],
				},
			}],
		}},
	}}

	p := {"allowed": {
		"/dev",
		"/tmp",
		"/usr",
	}}

	actual := v1.deny_host_path_not_in_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_deny_host_path_not_in_whitelist_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview", "request": {
			"kind": {"kind": "Pod"},
			"object": {"metadata": {"namespace": "prod"}, "spec": {
				"containers": [{
					"image": "nginx:v1.0.0",
					"name": "nginx",
					"volumeMounts": [
						{
							"mountPath": "/test-pd",
							"name": "test-volume-1",
						},
						{
							"mountPath": "/test-pd1",
							"name": "test-volume-2",
						},
					],
				}],
				"initContainers": [{
					"image": "opa:latest",
					"name": "opa",
					"volumeMounts": [{
						"mountPath": "/test-pd1",
						"name": "test-volume",
					}],
				}],
				"volumes": [
					{
						"name": "test-volume",
						"hostPath": {
							"path": "/etc",
							"type": "Directory",
						},
					},
					{
						"name": "test-volume-1",
						"configMap": {
							"name": "log-config",
							"items": [{
								"key": "log_level",
								"path": "log_level",
							}],
						},
					},
					{
						"name": "test-volume-2",
						"hostPath": {
							"path": "/data",
							"type": "Directory",
						},
					},
				],
			}},
		},
	}

	p := {"allowed": {
		"/dev",
		"/tmp",
		"/usr",
	}}

	actual := v1.deny_host_path_not_in_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_deny_host_path_not_in_whitelist_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Deployment"},
			"namespace": "prod",
			"object": {"spec": {
				"selector": {"matchLabels": {"app": "nginx"}},
				"replicas": 2,
				"template": {
					"metadata": {"labels": {"app": "nginx"}},
					"spec": {
						"initContainers": [{
							"image": "opa:latest",
							"name": "opa",
							"volumeMounts": [{
								"mountPath": "/test-pd1",
								"name": "test-volume",
							}],
						}],
						"containers": [{
							"name": "foo",
							"image": "container_image",
							"volumeMounts": [
								{
									"mountPath": "/test-pd",
									"name": "test-volume-1",
								},
								{
									"mountPath": "/test-pd1",
									"name": "test-volume-2",
								},
							],
						}],
						"volumes": [
							{
								"name": "test-volume",
								"hostPath": {
									"path": "/etc",
									"type": "Directory",
								},
							},
							{
								"name": "test-volume-1",
								"configMap": {
									"name": "log-config",
									"items": [{
										"key": "log_level",
										"path": "log_level",
									}],
								},
							},
							{
								"name": "test-volume-2",
								"hostPath": {
									"path": "/data",
									"type": "Directory",
								},
							},
						],
					},
				},
			}},
		},
	}

	p := {"allowed": {
		"/dev",
		"/tmp",
		"/usr",
	}}

	actual := v1.deny_host_path_not_in_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 2

	p_allowed := {"allowed": {
		"/etc",
		"/data",
	}}

	allowed := v1.deny_host_path_not_in_whitelist with data.library.parameters as p_allowed
		with input as in

	count(allowed) == 0
}

test_k8s_deny_host_path_not_in_whitelist_good {
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {"spec": {
			"containers": [{
				"image": "nginx:v1.0.0",
				"name": "nginx",
				"volumeMounts": [
					{
						"mountPath": "/test-pd1",
						"name": "test-volume-1",
					},
					{
						"mountPath": "/test-pd",
						"name": "test-volume-2",
					},
				],
			}],
			"initContainers": [{
				"image": "opa:latest",
				"name": "opa",
				"volumeMounts": [{
					"mountPath": "/test-pd1",
					"name": "test-volume",
				}],
			}],
			"volumes": [
				{
					"name": "test-volume",
					"hostPath": {
						"path": "/dev/testvolume",
						"type": "Directory",
					},
				},
				{
					"name": "test-volume-1",
					"configMap": {
						"name": "log-config",
						"items": [{
							"key": "log_level",
							"path": "log_level",
						}],
					},
				},
				{
					"name": "test-volume-2",
					"hostPath": {
						"path": "/tmp/test",
						"type": "Directory",
					},
				},
			],
		}},
	}}

	p := {"allowed": {
		"/dev/test*",
		"/tmp/*",
		"/usr",
	}}

	actual := v1.deny_host_path_not_in_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# recommendation for parameters
test_all_host_paths {
	deployment := {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"labels": {},
			"name": "frontend",
			"namespace": "default",
		},
		"spec": {
			"replicas": 2,
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {"labels": {"app": "nginx"}},
				"spec": {
					"containers": [{
						"image": "nginx:v1.0.0",
						"name": "nginx",
						"volumeMounts": [
							{
								"mountPath": "/test-pd1",
								"name": "test-volume-1",
							},
							{
								"mountPath": "/test-pd",
								"name": "test-volume-2",
							},
						],
					}],
					"initContainers": [{
						"image": "opa:latest",
						"name": "opa",
						"volumeMounts": [{
							"mountPath": "/test-pd1",
							"name": "test-volume",
						}],
					}],
					"volumes": [
						{
							"name": "test-volume",
							"hostPath": {
								"path": "/dev/testvolume",
								"type": "Directory",
							},
						},
						{
							"name": "test-volume-1",
							"configMap": {
								"name": "log-config",
								"items": [{
									"key": "log_level",
									"path": "log_level",
								}],
							},
						},
						{
							"name": "test-volume-2",
							"hostPath": {
								"path": "/tmp/test",
								"type": "Directory",
							},
						},
					],
				},
			},
		},
	}

	result := v1.all_host_paths with data.kubernetes.resources.deployments["default"].frontend as deployment
	result.allowed == {"/tmp/test", "/dev/testvolume"}
}

###################
# Node selectors

test_k8s_deny_pod_without_required_node_selectors_pod_bad {
	toleration := [
		{
			"operator": "Exists",
			"tolerationSeconds": 300,
			"effect": "NoExecute",
			"key": "node.kubernetes.io/not-ready",
		},
		{
			"operator": "Exists",
			"tolerationSeconds": 300,
			"effect": "NoExecute",
			"key": "node.kubernetes.io/unreachable",
		},
	]

	in := input_with_tolerations(toleration)

	p := {"selectors": {"nginx": {
		"disktype": "ssd",
		"networkSpeed": "high",
		"pci": true,
	}}}

	actual := v1.deny_pod_without_required_node_selectors with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_deny_pod_without_required_node_selectors_deployment_bad {
	in := input_with_deployment("nginx", "nginx")

	p := {"selectors": {"nginx": {
		"disktype": "ssd",
		"networkSpeed": "high",
		"pci": true,
	}}}

	actual := v1.deny_pod_without_required_node_selectors with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_deny_pod_without_required_node_selectors_replica_set_good {
	in := input_with_replica_set("nginx")

	p := {"selectors": {"php-redis": {"disktype": "ssd"}}}

	actual := v1.deny_pod_without_required_node_selectors with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Master toleration

test_k8s_block_master_toleration_no_key {
	toleration := [{"operator": "Exists"}]
	in := input_with_tolerations(toleration)
	actual := v1.block_master_toleration with input as in

	count(actual) == 1
	actual[reason]
	contains(reason, "nginx tolerates everything")
}

test_k8s_block_master_toleration_no_effect {
	in := input_with_deployment("nginx", "nginx")
	actual := v1.block_master_toleration with input as in

	count(actual) == 1
	actual[reason]
	contains(reason, "nginx-deployment tolerates master node taint")
}

test_k8s_block_master_toleration_master_bad {
	toleration := [{
		"key": "node-role.kubernetes.io/master",
		"operator": "Equal",
		"value": "true",
		"effect": "NoSchedule",
	}]

	in := input_with_tolerations(toleration)
	actual := v1.block_master_toleration with input as in

	count(actual) == 1
	actual[reason]
	contains(reason, "nginx tolerates master node taint")
}

test_k8s_block_master_toleration_master_good {
	toleration := [{
		"key": "key",
		"operator": "Equal",
		"value": "true",
		"effect": "NoSchedule",
	}]

	in := input_with_tolerations(toleration)
	actual := v1.block_master_toleration with input as in

	count(actual) == 0
}

test_k8s_block_master_toleration_master_replica_set_good {
	in := input_with_replica_set("nginx")
	actual := v1.block_master_toleration with input as in

	count(actual) == 0
}

test_k8s_deny_toleration_keys_in_blacklist_good {
	in := input_with_replica_set("nginx")
	p := {"prohibited_keys": {"node-role.kubernetes.io/master", "master"}}
	actual := v1.deny_toleration_keys_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_deny_toleration_keys_in_blacklist_bad {
	in := input_with_deployment("nginx", "nginx")
	p := {"prohibited_keys": {"node-role.kubernetes.io/master", "master"}}
	actual := v1.deny_toleration_keys_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 1
	actual[reason]
	contains(reason, "contains restricted toleration key node-role.kubernetes.io/master")
}

###################
# Prohibit nodeName

test_k8s_block_nodename_assignment_no_effect {
	in := input_with_deployment("nginx", "nginx")
	actual := v1.block_nodename_assignment with input as in

	count(actual) == 0
}

test_k8s_block_nodename_assignment_bad {
	in := input_with_nodename("kube-master.hooli.com")
	actual := v1.block_nodename_assignment with input as in

	count(actual) == 1
	actual[reason]
	reason == "Resource Pod/foo/nginx specifies a nodeName: kube-master.hooli.com"
}

test_k8s_block_nodename_assignment_exclude_daemonset {
	in := input_with_daemonset
	actual := v1.block_nodename_assignment with input as in

	count(actual) == 0
}

test_k8s_block_nodename_exclude_daemonset_pod {
	in := input_with_daemonset_pod_withnodename("kube-master.hooli.com")

	actual := v1.block_nodename_assignment with input as in

	count(actual) == 0
}

###################
# Privileged

test_k8s_block_privileged_mode_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_bad_init {
	in := input_with_pod_with_args_a({"initcontainers": {"nginx"}, "containers": {"nginx"}, "initContainerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_good {
	in := input_with_images({"containers": {"nginx"}})
	actual := v1.block_privileged_mode with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_good_no_sec_context {
	in := input_with_deployment("nginx", "nginx")
	actual := v1.block_privileged_mode with input as in

	count(actual) == 0
}

###################
# Read-only filesystem

test_k8s_missing_read_only_filesystem {
	in := input_with_images({"containers": {"nginx"}})
	actual := v1.missing_read_only_filesystem with input as in
	count(actual) == 1
}

test_k8s_missing_read_only_filesystem_both_containers {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	actual := v1.missing_read_only_filesystem with input as in

	count(actual) == 2
}

test_k8s_has_read_only_filesystem {
	in := input_with_images({"containers": {"nginx"}, "regular_root_read_only": true})
	actual := v1.missing_read_only_filesystem with input as in

	count(actual) == 0
}

test_k8s_has_read_only_filesystem_both_containers {
	in := input_with_images({
		"containers": {"nginx"}, "regular_root_read_only": true,
		"initcontainers": {"nginx"}, "init_root_read_only": true,
	})

	actual := v1.missing_read_only_filesystem with input as in

	count(actual) == 0
}

# TODO: Missing tests on readOnlyRootFilesystem not specified.

###################
# Liveness&Readiness probe policy

test_k8s_require_liveness_bad_no_liveness {
	in := input_readiness_only
	p := {"min_period_seconds": 10}
	actual := v1.require_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_require_liveness_no_liveness_job {
	in := input_job
	p := {"min_period_seconds": 10}
	actual := v1.require_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_require_liveness_no_liveness_cronjob {
	in := input_cronjob
	p := {"min_period_seconds": 10}
	actual := v1.require_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

input_job = in {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Job"},
			"namespace": "test",
			"object": {"spec": {"template": {"spec": {
				"containers": [{
					"name": "c",
					"image": "devopscube/kubernetes-job-demo:latest",
					"args": ["100"],
				}],
				"restartPolicy": "OnFailure",
			}}}},
		},
	}
}

input_cronjob = in {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "CronJob"},
			"namespace": "test",
			"object": {"spec": {
				"schedule": "*/1 * * * *",
				"jobTemplate": {"spec": {"template": {"spec": {
					"restartPolicy": "OnFailure",
					"containers": [{
						"name": "kube-cron-job",
						"image": "devopscube/kubernetes-job-demo:latest",
						"args": ["100"],
					}],
				}}}},
			}},
		},
	}
}

input_cronjob_with_init_container = in {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "CronJob"},
			"namespace": "test",
			"object": {"spec": {
				"schedule": "*/1 * * * *",
				"jobTemplate": {"spec": {"template": {"spec": {
					"restartPolicy": "OnFailure",
					"initContainers": [{
						"name": "init",
						"image": "devopscube/kubernetes-job-demo:latest",
						"args": ["100"],
					}],
					"containers": [{
						"name": "kube-cron-job",
						"image": "devopscube/kubernetes-job-demo:latest",
						"args": ["100"],
					}],
				}}}},
			}},
		},
	}
}

test_k8s_require_liveness_no_interval {
	in := input_liveness_missing_interval
	actual := v1.require_liveness_probe with input as in

	count(actual) == 0
}

test_k8s_require_liveness_bad_liveness_wrong_interval {
	in := input_liveness_interval_out_of_range
	p := {"min_period_seconds": 10}
	actual := v1.require_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_check_policy_bad_no_liveness {
	in := input_readiness_only
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_check_policy_liveness_no_interval {
	in := input_liveness_missing_interval
	actual := v1.ensure_liveness_probe with input as in

	count(actual) == 0
}

test_k8s_check_policy_bad_liveness_wrong_interval {
	in := input_liveness_interval_out_of_range
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_require_readiness_bad_no_readiness {
	in := input_liveness_only
	p := {"min_period_seconds": 10}
	actual := v1.require_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_require_readiness_no_interval {
	in := input_readiness_missing_interval
	actual := v1.require_readiness_probe with input as in

	count(actual) == 0
}

test_k8s_require_readiness_bad_readiness_wrong_interval {
	in := input_readiness_interval_out_of_range
	p := {"min_period_seconds": 10}
	actual := v1.require_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_check_policy_bad_no_readiness {
	in := input_liveness_only
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_check_policy_readiness_no_interval {
	in := input_readiness_missing_interval
	actual := v1.ensure_readiness_probe with input as in

	count(actual) == 0
}

test_k8s_check_policy_bad_readiness_wrong_interval {
	in := input_readiness_interval_out_of_range
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_check_liveness_policy_good {
	in := input_readiness_liveness
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_check_readiness_policy_good {
	in := input_readiness_liveness
	p := {"periodSecondsMin": 10}
	actual := v1.ensure_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_require_liveness_policy_good {
	in := input_readiness_liveness
	p := {"min_period_seconds": 10}
	actual := v1.require_liveness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_require_readiness_policy_good {
	in := input_readiness_liveness
	p := {"min_period_seconds": 10}
	actual := v1.require_readiness_probe with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Image Pull Policy

test_k8s_check_image_pull_policy_good {
	in := input_with_images({"containers": {"nginx"}})
	actual := v1.check_image_pull_policy with input as in

	count(actual) == 0
}

test_k8s_check_image_pull_policy_good_both_containers {
	in := input_with_image_pull({"containers": {"hooli/nginx:1.2"}, "regular_image_pull": "Always"})
	actual := v1.check_image_pull_policy with input as in

	count(actual) == 0
}

test_k8s_image_no_pull_policy_no_latest_tag {
	in := input_with_image_pull({"containers": {"hooli/nginx:1.2"}})
	actual := v1.check_image_pull_policy with input as in

	count(actual) == 1
}

test_k8s_image_valid_pull_policy_no_latest_tag {
	in := input_with_image_pull({
		"containers": {"hooli/nginx:1.2"}, "regular_image_pull": "Always",
		"initcontainers": {"hooli/nginx:1.2"}, "init_image_pull": "Always",
	})

	actual := v1.check_image_pull_policy with input as in

	count(actual) == 0
}

test_k8s_image_valid_pull_policy_never {
	in := input_with_image_pull({
		"containers": {"hooli/nginx:1.2"}, "regular_image_pull": "Never",
		"initcontainers": {"hooli/nginx:1.2"}, "init_image_pull": "Never",
	})

	actual := v1.check_image_pull_policy with input as in

	count(actual) == 2
}

test_k8s_image_valid_pull_policy_never {
	in := input_with_image_pull({
		"containers": {"nginx"}, "regular_image_pull": "Never",
		"initcontainers": {"nginx"}, "init_image_pull": "Never",
	})

	actual := v1.check_image_pull_policy with input as in

	count(actual) == 2
}

test_k8s_test_k8s_image_no_pull_policy_no_latest_tag_both {
	in := input_with_images({
		"containers": {"acme.com/foo/bar:0.2"},
		"initcontainers": {"acme.com/foo/bar:0.2"},
	})

	actual := v1.check_image_pull_policy with input as in

	count(actual) == 2
}

test_k8s_test_k8s_image_no_pull_policy_both_latest_tag {
	in := input_with_deployment("nginx", "nginx")
	actual := v1.check_image_pull_policy with input as in

	count(actual) == 0
}

###################
# Allowed Reclaim Policy

test_deny_unexpected_reclaim_policy_good {
	reclaim_policy := "Retain"

	classes := {"storage_class": {
		"kind": "StorageClass",
		"reclaimPolicy": reclaim_policy,
	}}

	claims := {"ns": {"test-claim": {
		"kind": "PersistentVolumeClaim",
		"spec": {"storageClassName": "storage_class"},
	}}}

	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"namespace": "prod"},
				"spec": {
					"containers": [{
						"name": "nginx",
						"volumeMounts": [{"name": "test-volume"}],
					}],
					"volumes": [{
						"name": "test-volume",
						"claimName": "test-claim",
					}],
				},
			},
		},
	}

	p := {"reclaim_policy": reclaim_policy}

	actual := v1.deny_unexpected_reclaim_policy with input as in
		with data.kubernetes.resources.persistentvolumeclaims as claims
		with data.kubernetes.resources.storageclasses as classes
		with data.library.parameters as p

	count(actual) == 0
}

test_deny_unexpected_reclaim_policy_bad {
	reclaim_policy := "Retain"

	classes := {"storage_class": {
		"kind": "StorageClass",
		"reclaimPolicy": "Delete",
	}}

	claims := {"ns": {"test-claim": {
		"kind": "PersistentVolumeClaim",
		"spec": {"storageClassName": "storage_class"},
	}}}

	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {
			"metadata": {"namespace": "ns"},
			"spec": {
				"containers": [{
					"name": "nginx",
					"volumeMounts": [{"name": "test-volume"}],
				}],
				"volumes": [{
					"name": "test-volume",
					"persistentVolumeClaim": {"claimName": "test-claim"},
				}],
			},
		},
	}}

	p := {"reclaim_policy": reclaim_policy}

	actual := v1.deny_unexpected_reclaim_policy with input as in
		with data.kubernetes.resources.persistentvolumeclaims as claims
		with data.kubernetes.resources.storageclasses as classes
		with data.library.parameters as p

	count(actual) == 1
}

test_all_reclaim_policies {
	classes := {"storage_class": {
		"kind": "StorageClass",
		"reclaimPolicy": "Delete",
	}}

	claims := {"ns": {"test-claim": {
		"kind": "PersistentVolumeClaim",
		"spec": {"storageClassName": "storage_class"},
	}}}

	deployment := {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "frontend",
			"namespace": "ns",
		},
		"spec": {
			"replicas": 2,
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {},
				"spec": {
					"containers": [{
						"name": "nginx",
						"volumeMounts": [{"name": "test-volume"}],
					}],
					"volumes": [{
						"name": "test-volume",
						"persistentVolumeClaim": {"claimName": "test-claim"},
					}],
				},
			},
		},
	}

	res := v1.universal_reclaim_policy with data.kubernetes.resources.deployments.ns.frontend as deployment
		with data.kubernetes.resources.persistentvolumeclaims as claims
		with data.kubernetes.resources.storageclasses as classes

	res.reclaim_policy == "Delete"
}

###################
# Pod Priority

# TODO(k8s): handle existing Priority admission controller
test_deny_pod_with_priority_out_of_bounds_good_pod {
	in := pod_input_with_priority({"priority": "test_priority"})
	p := {"min": 500, "max": 2000}
	r := priority_class_resource(1000)
	actual := v1.deny_pod_with_priority_out_of_bounds with input as in
		with data.library.parameters as p
		with data.kubernetes.resources as r

	count(actual) == 0
}

priority_class_resource(priority) = result {
	result := {"priorityclasses": {"test_priority": {
		"apiVersion": "scheduling.k8s.io/v1",
		"kind": "PriorityClass",
		"metadata": {"name": "test_priority"},
		"value": priority,
		"globalDefault": false,
		"description": "Test.",
	}}}
}

# TODO(k8s): handle existing Priority admission controller
test_deny_pod_with_priority_out_of_bounds_below_min_pod_spec {
	in := pod_input_with_priority({"priority": "test_priority"})
	r := priority_class_resource(1000)
	p := {"min": 1500, "max": 2000}
	actual := v1.deny_pod_with_priority_out_of_bounds with input as in
		with data.library.parameters as p
		with data.kubernetes.resources as r

	count(actual) == 1
}

# TODO(k8s): handle existing Priority admission controller
test_deny_pod_with_priority_out_of_bounds_above_max_pod_spec {
	in := pod_input_with_priority({"priority": "test_priority"})
	p := {"min": 0, "max": 500}
	r := priority_class_resource(1000)
	actual := v1.deny_pod_with_priority_out_of_bounds with input as in
		with data.library.parameters as p
		with data.kubernetes.resources as r

	count(actual) == 1
}

# TODO(k8s): handle existing Priority admission controller
test_deny_pod_with_priority_out_of_bounds_min_greater_than_max_pod_spec {
	in := pod_input_with_priority({"priority": "test_priority"})
	p := {"min": 2000, "max": 1}
	r := priority_class_resource(1000)
	actual := v1.deny_pod_with_priority_out_of_bounds with input as in
		with data.library.parameters as p
		with data.kubernetes.resources as r

	# Expect 2 because it is both above max and below the min at the same time.. There
	# should be two distinct error messages explaining each failure.
	count(actual) == 2
}

# TODO(k8s): handle existing Priority admission controller
test_deny_pod_with_priority_out_of_bounds_not_set_pod_spec {
	in := input_with_images({"containers": {"nginx"}})
	p := {"min": 10, "max": 1}
	actual := v1.deny_pod_with_priority_out_of_bounds with input as in
		with data.library.parameters as p

	count(actual) == 0
}

# NodePort

test_k8s_check_nodeport_good {
	in := input_readiness_only
	actual := v1.expect_no_nodeport with input as in

	count(actual) == 0
}

test_k8s_run_as_root_pod_good {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"securityContext": {"runAsUser": 1000},
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
					}],
				},
			},
		},
	}

	actual := v1.ensure_no_run_as_root with input as in
	count(actual) == 0
}

# Require update strategy

#  The case where there is no update strategy in Deployment is not tested because
#  there will be default value for this.

test_k8s_wrong_update_strategy {
	strategy := {"type": "RollingUpdate"}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "xx"}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_good_update_strategy {
	strategy := {"type": "RollingUpdate"}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate"}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_check_nodeport_bad {
	in := input_nodeport
	actual := v1.expect_no_nodeport with input as in
	count(actual) == 1
}

test_k8s_updates_strategy_wrong_value_available {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 30}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_unavailable_min": 40}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_run_as_root_container_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "nginx",
					"imagePullPolicy": "Never",
					"name": "nginx",
					"securityContext": {"runAsUser": 0},
				}]},
			},
		},
	}

	actual := v1.ensure_no_run_as_root with input as in
	count(actual) == 1
}

test_k8s_run_as_root_container_excluded {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "nginx",
					"imagePullPolicy": "Never",
					"name": "nginx",
					"securityContext": {"runAsUser": 0},
				}]},
			},
		},
	}

	p := {"exclude": {"": {"nginx"}}}

	actual := v1.ensure_no_run_as_root with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_run_as_root_pod_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"securityContext": {"runAsUser": 0},
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
					}],
				},
			},
		},
	}

	actual := v1.ensure_no_run_as_root with input as in
	count(actual) == 1
}

test_k8s_updates_strategy_wrong_value2 {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 30}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_surge_min": 40}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_run_as_root_pod_good {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {
					"securityContext": {"runAsUser": 1000},
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
					}],
				},
			},
		},
	}

	actual := v1.ensure_no_run_as_root with input as in

	count(actual) == 0
}

test_k8s_run_as_root_pod_container_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"spec": {"securityContext": {"runAsUser": 1000}},
			"object": {
				"metadata": {"name": "foo", "namespace": "prod"},
				"spec": {"containers": [{
					"image": "nginx",
					"imagePullPolicy": "Never",
					"name": "nginx",
					"securityContext": {"runAsUser": 0},
				}]},
			},
		},
	}

	actual := v1.ensure_no_run_as_root with input as in
	count(actual) == 1
}

test_k8s_updates_strategy_wrong_value_percentage_req {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": "30%"}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_surge_min": 40}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_updates_strategy_wrong_value_percentage_para {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 30}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_surge_min": "40%"}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_updates_strategy_wrong_value_percentage_both {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": "30%"}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_surge_min": "40%"}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_updates_strategy_good_value {
	strategy := {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 5, "maxUnavailable": 5}}
	in := input_for_update_strategy(strategy)
	p = {"update_strategy": "RollingUpdate", "max_surgeMin": 4, "max_unavailable_min": 4}
	actual := v1.require_update_strategy with data.library.parameters as p
		with input as in

	count(actual) == 0
}

###################
# Inputs

input_nodeport = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Service"},
			"namespace": "test",
			"object": {"spec": {
				"type": "NodePort",
				"selector": {"app": "echo-hostname"},
				"ports": [{
					"nodePort": 30163,
					"port": 8080,
					"targetPort": 80,
				}],
			}},
		},
	}
}

input_for_update_strategy(strategy) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Deployment"},
			"namespace": "prod",
			"object": {"spec": {
				"selector": {"matchLabels": {"app": "nginx"}},
				"replicas": 100,
				"strategy": strategy,
				"template": {
					"metadata": {"labels": {"app": "nginx"}},
					"spec": {"containers": [{
						"image": "nginx",
						"name": "nginx",
						"readinessProbe": {
							"tcpSocket": {"port": 8080},
							"initialDelaySeconds": 5,
							"periodSeconds": 10,
						},
					}]},
				},
			}},
		},
	}
}

input_readiness_only = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {
				"hostNetwork": true,
				"containers": [{
					"image": "test",
					"name": "test",
					"readinessProbe": {
						"tcpSocket": {"port": 8080},
						"initialDelaySeconds": 5,
						"periodSeconds": 10,
					},
				}],
			}},
		},
	}
}

input_liveness_missing_interval = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"livenessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
				},
			}]}},
		},
	}
}

input_liveness_interval_out_of_range = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"livenessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
					"periodSeconds": 1,
				},
			}]}},
		},
	}
}

input_liveness_only = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"livenessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
					"periodSeconds": 10,
				},
			}]}},
		},
	}
}

input_readiness_missing_interval = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"readinessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
				},
			}]}},
		},
	}
}

input_readiness_interval_out_of_range = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"readinessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
					"periodSeconds": 1,
				},
			}]}},
		},
	}
}

input_readiness_liveness = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "test",
			"object": {"spec": {"containers": [{
				"image": "test",
				"name": "test",
				"readinessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
					"periodSeconds": 20,
				},
				"livenessProbe": {
					"tcpSocket": {"port": 8080},
					"initialDelaySeconds": 5,
					"periodSeconds": 20,
				},
			}]}},
		},
	}
}

input_with_deployment(container_name, container_image) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Deployment"},
			"object": {
				"spec": {
					"selector": {"matchLabels": {"app": "nginx"}},
					"template": {
						"spec": {
							"containers": [{
								"terminationMessagePath": "/dev/termination-log",
								"name": container_name,
								"image": container_image,
								"terminationMessagePolicy": "File",
								"ports": [{
									"protocol": "TCP",
									"containerPort": 80,
								}],
								"resources": {},
							}],
							"initContainers": [],
							"nodeSelector": {"disktype": "ssd"},
							"tolerations": [{
								"key": "node-role.kubernetes.io/master",
								"operator": "Exists",
							}],
						},
						"metadata": {
							"labels": {"app": "nginx"},
							"name": "nginx",
							"creationTimestamp": null,
						},
					},
				},
				"metadata": {
					"name": "nginx-deployment",
					"labels": {"app": "nginx"},
					"namespace": "prod",
				},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

# ImagePullTest
input_with_image_pull(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	name := get(args, "name", "foo")
	regular_image_pull := get(args, "regular_image_pull", "IfNotPresent")
	init_image_pull := get(args, "init_image_pull", "IfNotPresent")
	procMount := get(args, "procMount", "Default")
	containers := [{
		"image": image,
		"name": "nginx",
		"imagePullPolicy": regular_image_pull,
		"securityContext": {"procMount": procMount},
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"imagePullPolicy": init_image_pull,
		"securityContext": {"procMount": procMount},
	} |
		init_images[image]
	]

	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": name},
				"spec": {
					"containers": containers,
					"initContainers": initContainers,
				},
			},
		},
	}
}

# Note: each container/initcontainer should have its own privileged/secContext/etc
#   specifiable as part of args.
input_with_images(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	init_privileged := get(args, "init_privileged", false)
	regular_privileged := get(args, "regular_privileged", false)
	regular_allow_privilege_escalation := get(args, "regular_allow_privilege_escalation", false)
	regular_root_read_only := get(args, "regular_root_read_only", false)
	init_root_read_only := get(args, "init_root_read_only", false)
	init_allow_privilege_escalation := get(args, "init_allow_privilege_escalation", false)
	procMount := get(args, "procMount", "Default")
	podSecurityContext := get(args, "podSecurityContext", {})
	annotations := get(args, "annotations", {})
	containerSecurityContextA := get(args, "containerSecurityContext", {"runAsUser": -1})
	name := get(args, "name", "foo")
	userGroups := get(args, "userGroups", [])

	initContainerSecurityContext := {
		"readOnlyRootFilesystem": init_root_read_only,
		"privileged": init_privileged,
		"allowPrivilegeEscalation": init_allow_privilege_escalation,
		"procMount": procMount,
	}

	containerSecurityContextB := {
		"privileged": regular_privileged,
		"readOnlyRootFilesystem": regular_root_read_only,
		"allowPrivilegeEscalation": regular_allow_privilege_escalation,
		"procMount": procMount,
	}

	containerSecurityContext := get_security_context(containerSecurityContextA.runAsUser, containerSecurityContextB)

	containers := [{
		"image": image,
		"name": "nginx",
		"securityContext": containerSecurityContext,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"securityContext": initContainerSecurityContext,
	} |
		init_images[image]
	]

	metadata := {
		"name": name,
		"annotations": annotations,
	}

	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {
				"groups": userGroups,
				"username": "alice",
			},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": metadata,
				"spec": {
					"containers": containers,
					"initContainers": initContainers,
					"securityContext": podSecurityContext,
				},
			},
		},
	}
}

input_with_pod_with_args_a(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	annotations := get(args, "annotations", {})
	podSecurityContext := get(args, "podSecurityContext", {})
	containerSecurityContext := get(args, "containerSecurityContext", {})
	initContainerSecurityContext := get(args, "initContainerSecurityContext", {})
	name := get(args, "name", "foo")

	containers := [{
		"image": image,
		"name": "nginx",
		"securityContext": containerSecurityContext,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"securityContext": initContainerSecurityContext,
	} |
		init_images[image]
	]

	metadata := {
		"name": name,
		"annotations": annotations,
	}

	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": metadata,
				"spec": {
					"containers": containers,
					"initContainers": initContainers,
					"securityContext": podSecurityContext,
				},
			},
		},
	}
}

name_from_image(image) = name {
	name1 := replace(image, "/", "-")
	name2 := replace(name1, ".", "-")
	name3 := replace(name2, ":", "-")
	name := name3
}

# construct_containers(images, privileged) = containerz {
# 	count(images) > 0
# 	containerz := [{
# 		"image": image,
# 		"imagePullPolicy": "Never",
# 		"name": "foo",
# 		"securityContext": {"privileged": privileged},
# 	} |
# 		images[image]
# 	]
# }

# construct_containers(images, privileged) = cs {
# 	count(images) == 0
# 	cs := [{
# 		"image": "foo",
# 		"name": "foo",
# 		"securityContext": {"privileged": privileged},
# 	}]
# }

get(args, key, default_value) = x {
	x := args[key]
}

get(args, key, default_value) = default_value {
	not args[key]
}

input_with_tolerations(toleration) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"status": {
					"phase": "Pending",
					"qosClass": "BestEffort",
				},
				"spec": {
					"nodeSelector": {"disktype": "ssd"},
					"tolerations": toleration,
					"containers": [{
						"image": "nginx",
						"name": "nginx",
					}],
				},
				"metadata": {
					"labels": {"env": "test"},
					"namespace": "foo",
					"name": "nginx",
					"uid": "549e5bea-1d5e-11e9-8736-08002743f811",
				},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_with_daemonset_pod_withnodename(nodename) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"status": {
					"phase": "Pending",
					"qosClass": "BestEffort",
				},
				"spec": {
					"nodeName": nodename,
					"containers": [{
						"image": "httpd",
						"name": "httpd",
					}],
				},
				"metadata": {
					"labels": {"env": "test"},
					"namespace": "foo",
					"name": "httpd",
					"uid": "549e5bea-1d5e-11e9-8736-08002743f811",
					"ownerReferences": [{
						"apiVersion": "apps/v1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "DaemonSet",
						"name": "logging",
						"uid": "2d35e6dd-344e-4720-9d46-ecbdde7d6548",
					}],
				},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_with_daemonset = {
	"kind": "AdmissionReview",
	"request": {
		"kind": {"kind": "DaemonSet"},
		"object": {
			"spec": {
				"selector": {"matchLabels": {"name": "httpd"}},
				"template": {
					"metadata": {"labels": {"name": "httpd"}},
					"spec": {"containers": [{
						"image": "httpd",
						"name": "webserver",
					}]},
				},
			},
			"metadata": {
				"labels": {"env": "test"},
				"name": "httpd",
			},
		},
		"namespace": "foo",
		"operation": "CREATE",
	},
	"apiVersion": "admission.k8s.io/v1beta1",
}

input_with_nodename(nodename) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"status": {
					"phase": "Pending",
					"qosClass": "BestEffort",
				},
				"spec": {
					"nodeName": nodename,
					"containers": [{
						"image": "nginx",
						"name": "nginx",
					}],
				},
				"metadata": {
					"labels": {"env": "test"},
					"namespace": "foo",
					"name": "nginx",
					"uid": "549e5bea-1d5e-11e9-8736-08002743f811",
				},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_with_replica_set(imagename) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "ReplicaSet"},
			"object": {
				"spec": {
					"selector": {"matchLabels": {"app": "guestbook"}},
					"template": {
						"spec": {
							"nodeSelector": {"disktype": "ssd"},
							"tolerations": [{
								"operator": "Equal",
								"value": "world",
								"key": "hello",
								"effect": "NoSchedule",
							}],
							"containers": [{
								"terminationMessagePath": "/dev/termination-log",
								"name": name_from_image(imagename),
								"image": imagename,
								"imagePullPolicy": "IfNotPresent",
								"resources": {"requests": {
									"cpu": "100m",
									"memory": "100Mi",
								}},
							}],
						},
						"metadata": {
							"labels": {
								"tier": "frontend",
								"app": "guestbook",
							},
							"name": "nginx",
							"annotations": {"costcenter": "commercial"},
						},
					},
					"replicas": 3,
				},
				"metadata": {
					"name": "frontend",
					"generation": 1,
					"labels": {
						"tier": "frontend",
						"app": "guestbook",
					},
					"namespace": "prod",
				},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

pod_input_with_priority(args) = x {
	priority := get(args, "priority", "test_priority")
	namespace := get(args, "namespace", "prod")
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": namespace,
			"object": {
				"metadata": {"name": "foo", "namespace": namespace},
				"spec": {
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
						"securityContext": {"privileged": false},
					}],
					"initContainers": [],
					"priorityClassName": priority,
				},
			},
		},
	}
}

pod_input_with_namespace(namespace) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": namespace,
			"object": {
				"metadata": {"name": "foo", "namespace": namespace},
				"spec": {
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
						"securityContext": {"privileged": false},
					}],
					"initContainers": [],
				},
			},
		},
	}
}

pod_input_with_missing_namespace = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "foo"},
				"spec": {
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "Never",
						"name": "nginx",
						"securityContext": {"privileged": false},
					}],
					"initContainers": [],
				},
			},
		},
	}
}

test_deny_namespace_in_blacklist_ok {
	in := input_with_tolerations({"operator": "Exists"})
	p := {"prohibited_namespaces": {"test"}}
	actual := v1.deny_namespace_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_deny_namespace_in_blacklist_fail {
	in := input_with_tolerations({"operator": "Exists"})
	p := {"prohibited_namespaces": {"foo"}}
	actual := v1.deny_namespace_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_deny_namespace_in_blacklist_no_parameters {
	in := input_with_tolerations({"operator": "Exists"})
	actual := v1.deny_namespace_in_blacklist with input as in

	count(actual) == 0
}

test_deny_namespace_in_blacklist_service_account_ok {
	in := input_create_service_account("system:serviceaccount:nstest:satest", {"system:serviceaccounts", "system:serviceaccounts:nstest"})

	p := {"prohibited_namespaces": {"build-robot"}}
	actual := v1.deny_namespace_in_blacklist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

input_create_service_account(user, groups) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userInfo": {"username": user, "groups": groups},
			"kind": {"kind": "ServiceAccount"},
			"operation": "CREATE",
			"object": {
				"metadata": {
					"creationTimestamp": "2015-06-16T00:12:59.000Z",
					"name": "build-robot",
					"namespace": "defppp",
					"resourceVersion": "272500",
					"uid": "721ab723-13bc-11e5-aec2-42010af0021e",
				},
				"secrets": [{"name": "build-robot-token-bvbk5"}],
			},
		},
	}
}

test_k8s_deny_retain_policy_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "StorageClass"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "standard"},
				"provisioner": "kubernetes.io/aws-ebs",
				"parameters": {"type": "gp2"},
				"reclaimPolicy": "Retain",
				"allowVolumeExpansion": true,
				"mountOptions": ["debug"],
				"volumeBindingMode": "Immediate",
			},
		},
	}

	actual := v1.deny_retain_policy with input as in
	count(actual) == 1
}

# By default, the reclaim policy will be "Delete"
test_deny_retain_policy_bad_default {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "StorageClass"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "standard"},
				"provisioner": "kubernetes.io/aws-ebs",
				"parameters": {"type": "gp2"},
				"allowVolumeExpansion": true,
				"mountOptions": ["debug"],
				"volumeBindingMode": "Immediate",
			},
		},
	}

	actual := v1.deny_retain_policy with input as in
	count(actual) == 0
}

## invalid_replicas tests
test_deny_retain_policy_good {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "StorageClass"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "standard"},
				"provisioner": "kubernetes.io/aws-ebs",
				"parameters": {"type": "gp2"},
				"reclaimPolicy": "Delete",
				"allowVolumeExpansion": true,
				"mountOptions": ["debug"],
				"volumeBindingMode": "Immediate",
			},
		},
	}

	actual := v1.deny_retain_policy with input as in
	count(actual) == 0
}

test_invalid_replicas_deployment_bad0 {
	parameters := {}
	in := input_replicas_with_kind(-1, "Deployment")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 1
}

test_invalid_replicas_deployment_bad1 {
	parameters := {"replica_count": -1}
	in := input_replicas_with_kind(-1, "Deployment")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 1
}

test_invalid_replicas_deployment_bad2 {
	parameters := {"replica_count": 1}
	in := input_replicas_with_kind(-1, "Deployment")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 1
}

test_invalid_replicas_replicaset_good3 {
	parameters := {"replica_count": 2}
	in := input_replicas_with_kind(2, "Deployment")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 0
}

test_invalid_replicas_replicaset_good4 {
	parameters := {"replica_count": 2}
	in := input_replicas_with_kind(4, "Deployment")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 0
}

test_invalid_replicas_replicaset_good5 {
	parameters := {"replica_count": 2}
	in := input_replicas_with_kind(4, "ReplicaSet")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 0
}

test_invalid_replicas_replicaset_good6 {
	parameters := {"replica_count": 4}
	in := input_replicas_with_kind(2, "ReplicaSet")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 0
}

test_invalid_replicas_nokind_good7 {
	parameters := {"replica_count": 2}
	in := input_replicas_with_kind(3, "SomeKind")
	actual := v1.deny_invalid_replicas with input as in
		with data.library.parameters as parameters

	count(actual) = 0
}

input_replicas_with_kind(replicas, kind) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": kind},
			"object": {"spec": {"replicas": replicas}},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

###################
# allowPrivilegeEscalation

test_k8s_deny_privilege_escalation_bad {
	in := input_with_images({"containers": {"nginx"}, "regular_allow_privilege_escalation": true})
	actual := v1.deny_privilege_escalation with input as in

	count(actual) == 1
}

test_k8s_deny_privilege_escalation_bad_init {
	in := input_with_images({"initcontainers": {"nginx"}, "containers": {"nginx"}, "init_allow_privilege_escalation": true})
	actual := v1.deny_privilege_escalation with input as in

	count(actual) == 1
}

test_k8s_deny_privilege_escalation_good {
	in := input_with_images({"containers": {"nginx"}})
	actual := v1.deny_privilege_escalation with input as in

	count(actual) == 0
}

test_k8s_deny_privilege_escalation_bad_no_sec_context {
	in := input_with_deployment("nginx", "nginx")
	actual := v1.deny_privilege_escalation with input as in

	count(actual) == 1
}

# procMount pod
test_k8s_skip_enforce_proc_mount_type_whitelist_pod_unmasked_good {
	in := input_with_image_pull({"containers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_skip_enforce_proc_mount_type_whitelist_pod_unmasked_bad {
	in := input_with_image_pull({"containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

test_k8s_enforce_proc_mount_type_whitelist_pod_dafault_good {
	in := input_with_image_pull({"containers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_enforce_proc_mount_type_whitelist_pod_default_bad {
	in := input_with_image_pull({"containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# procMount deployment
test_k8s_skip_enforce_proc_mount_type_whitelist_deployment_unmasked_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_skip_enforce_proc_mount_type_whitelist_deployment_unmasked_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

test_k8s_enforce_proc_mount_type_whitelist_deployment_dafault_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_enforce_proc_mount_type_whitelist_deployment_default_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# procMount replicaset
test_k8s_skip_enforce_proc_mount_type_whitelist_replicaset_unmasked_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_skip_enforce_proc_mount_type_whitelist_replicaset_unmasked_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Unmasked"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

test_k8s_enforce_proc_mount_type_whitelist_replicaset_dafault_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

test_k8s_enforce_proc_mount_type_whitelist_replicaset_default_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "procMount": "Default"})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# procMount with multiple containers..
# skipping test because this requires the ProcMountType feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_proc_mount_type_whitelist_deploy_multiple_containers_bad1 {
	in := input_deployment_with_args({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"procMount": "Default"}, "initContainerSecurityContext": {"procMount": "Default"}})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# skipping test because this requires the ProcMountType feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_proc_mount_type_whitelist_deploy_multiple_containers_bad2 {
	in := input_deployment_with_args({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"procMount": "Default"}, "initContainerSecurityContext": {"procMount": "Unmasked"}})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# skipping test because this requires the ProcMountType feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_proc_mount_type_whitelist_deploy_multiple_containers_bad3 {
	in := input_deployment_with_args({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"procMount": "Default"}})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) >= 1
}

# skipping test because this requires the ProcMountType feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_proc_mount_type_whitelist_deploy_multiple_containers_good {
	in := input_deployment_with_args({"containers": {"nginx"}, "initcontainers": {"nginx"}, "initContainerSecurityContext": {"procMount": "Default"}})
	p := {"whitelist": ["Default"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

# skipping test because this requires the ProcMountType feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_proc_mount_type_whitelist_deploy_multiple_containers_good1 {
	in := input_deployment_with_args({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"procMount": "Unmasked"}, "initContainerSecurityContext": {"procMount": "Unmasked"}})
	p := {"whitelist": ["Unmasked"]}
	actual := v1.enforce_proc_mount_type_whitelist with data.library.parameters as p with input as in
	count(actual) == 0
}

get_security_context(runAsUser, containerSecurityContext) = x {
	runAsUser == -1
	x := containerSecurityContext
}

get_security_context(runAsUser, containerSecurityContext) = x {
	runAsUser != -1
	x := {"runAsUser": runAsUser}
}

input_pod_controller_with_args(args) = x {
	kind := get(args, "kind", "Deployment")
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	init_privileged := get(args, "init_privileged", false)
	regular_privileged := get(args, "regular_privileged", false)
	regular_allow_privilege_escalation := get(args, "regular_allow_privilege_escalation", false)
	regular_root_read_only := get(args, "regular_root_read_only", false)
	init_root_read_only := get(args, "init_root_read_only", false)
	init_allow_privilege_escalation := get(args, "init_allow_privilege_escalation", false)
	annotations := get(args, "annotations", {})
	name := get(args, "name", "foo")
	podSecurityContext := get(args, "podSecurityContext", {})
	containerSecurityContextA := get(args, "containerSecurityContext", {"runAsUser": -1})
	procMount := get(args, "procMount", "Default")

	containerSecurityContextB := {
		"readOnlyRootFilesystem": init_root_read_only,
		"privileged": init_privileged,
		"allowPrivilegeEscalation": init_allow_privilege_escalation,
		"procMount": procMount,
	}

	containerSecurityContext := get_security_context(containerSecurityContextA.runAsUser, containerSecurityContextB)

	containers := [{
		"image": image,
		"name": "nginx",
		"securityContext": containerSecurityContext,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"securityContext": containerSecurityContext,
	} |
		init_images[image]
	]

	metadata := {
		"name": name,
		"annotations": annotations,
		"labels": {"app": "nginx"},
		"creationTimestamp": null,
	}

	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": kind},
			"object": {
				"spec": {
					"selector": {"matchLabels": {"app": "nginx"}},
					"template": {
						"spec": {
							"containers": containers,
							"initContainers": initContainers,
							"nodeSelector": {"disktype": "ssd"},
							"tolerations": [{
								"key": "node-role.kubernetes.io/master",
								"operator": "Exists",
							}],
							"securityContext": podSecurityContext,
						},
						"metadata": metadata,
					},
				},
				"metadata": {
					"name": "nginx-pod-controller",
					"labels": {"app": "nginx"},
					"namespace": "prod",
				},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

# input a deployment with securityContext(pod,container,initContainer level)
input_deployment_with_args(args) = x {
	kind := get(args, "kind", "Deployment")
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	annotations := get(args, "annotations", {})
	name := get(args, "name", "foo")
	podSecurityContext := get(args, "podSecurityContext", {})
	containerSecurityContext := get(args, "containerSecurityContext", {})
	initContainerSecurityContext := get(args, "initContainerSecurityContext", {})
	procMount := get(args, "procMount", "Default")

	containers := [{
		"image": image,
		"name": image,
		"securityContext": containerSecurityContext,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": image,
		"securityContext": initContainerSecurityContext,
	} |
		init_images[image]
	]

	metadata := {
		"name": name,
		"annotations": annotations,
		"labels": {"app": "nginx"},
		"creationTimestamp": null,
	}

	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": kind},
			"object": {
				"spec": {
					"selector": {"matchLabels": {"app": "nginx"}},
					"template": {
						"spec": {
							"containers": containers,
							"initContainers": initContainers,
							"securityContext": podSecurityContext,
						},
						"metadata": metadata,
					},
				},
				"metadata": {
					"name": "nginx-pod-controller",
					"labels": {"app": "nginx"},
					"namespace": "prod",
				},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_pod_controller_with_args_a(args) = x {
	kind := get(args, "kind", "Deployment")
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	annotations := get(args, "annotations", {})
	name := get(args, "name", "foo")
	podSecurityContext := get(args, "podSecurityContext", {})
	containerSecurityContext := get(args, "containerSecurityContext", {})
	initContainerSecurityContext := get(args, "initContainerSecurityContext", {})
	containers := [{
		"image": image,
		"name": "nginx",
		"securityContext": containerSecurityContext,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"securityContext": initContainerSecurityContext,
	} |
		init_images[image]
	]

	metadata := {
		"name": name,
		"annotations": annotations,
		"labels": {"app": "nginx"},
		"creationTimestamp": null,
	}

	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": kind},
			"object": {
				"spec": {
					"selector": {"matchLabels": {"app": "nginx"}},
					"template": {
						"spec": {
							"containers": containers,
							"initContainers": initContainers,
							"securityContext": podSecurityContext,
						},
						"metadata": metadata,
					},
				},
				"metadata": {
					"name": "nginx-pod-controller",
					"labels": {"app": "nginx"},
					"namespace": "prod",
				},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

test_k8s_enforce_app_armor_profile_whitelist_pod_good {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_app_armor_profile_whitelist_pod_initcontainer_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_app_armor_profile_whitelist_pod_wildcard_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_app_armor_profile_whitelist_pod_multiple_parameters_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["localhost/k8s-apparmor-example-deny-write", "runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_app_armor_profile_whitelist_deployment_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_app_armor_profile_whitelist_deployment_wildcard_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "localhost/k8s-apparmor-example-deny-write"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_app_armor_profile_whitelist_replicaset_wildcard_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_app_armor_profile_whitelist_pod_bad {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["localhost/k8s-apparmor-example-deny-write"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because this requires the AppArmor feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_app_armor_profile_whitelist_pod_initcontainer_without_annotation_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_app_armor_profile_whitelist_deployment_bad {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "localhost/k8s-apparmor-example-deny-write"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because this requires the AppArmor feature flag to be enabled on k8s cluster.
test_k8s_skip_enforce_app_armor_profile_whitelist_deployment_initcontainer_without_annotation_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_app_armor_profile_whitelist_replicaset_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["localhost/k8s-apparmor-example-deny-write"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# multiple containers with multiple annotations
test_k8s_enforce_app_armor_profile_whitelist_deployment_initcontainer_pod_level_1_bad {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default", "container.apparmor.security.beta.kubernetes.io/busybox": "localhost/k8s-apparmor-example-deny-write"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_app_armor_profile_whitelist_deployment_initcontainer_pod_level_2_bad {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default", "container.apparmor.security.beta.kubernetes.io/busybox": "runtime/default"}})
	p := {"whitelist": ["localhost/k8s-apparmor-example-deny-write"]}

	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_app_armor_profile_whitelist_deployment_initcontainer_pod_level_1_good {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"container.apparmor.security.beta.kubernetes.io/nginx": "runtime/default", "container.apparmor.security.beta.kubernetes.io/busybox": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_app_armor_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# seccomp tests
test_k8s_enforce_seccomp_profile_whitelist_pod_good {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_pod_initcontainer_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_seccomp_profile_whitelist_pod_wildcard_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_pod_multiple_parameters_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["docker/default", "runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_initcontainer_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_wildcard_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "docker/default"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_replicaset_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_replicaset_wildcard_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["*"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_pod_pod_level_good {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_replicaset_initcontainer_pod_level_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_initcontainer_pod_level_good {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_seccomp_profile_whitelist_pod_bad {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because the Seccomp feature is disabled by default on k8s cluster and must be allowed manually by the cluster admin
test_k8s_skip_enforce_seccomp_profile_whitelist_pod_initcontainer_without_annotation_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_bad {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "docker/default"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because the Seccomp feature is disabled by default on k8s cluster and must be allowed manually by the cluster admin
test_k8s_skip_enforce_seccomp_profile_whitelist_deployment_initcontainer_without_annotation_bad {
	in := input_with_images({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because the Seccomp feature is disabled by default on k8s cluster and must be allowed manually by the cluster admin
test_k8s_skip_enforce_seccomp_profile_whitelist_replicaset_initcontainer_without_annotation_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"whitelist": ["runtime/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_pod_pod_level_bad {
	in := input_with_images({"containers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_replicaset_initcontainer_pod_level_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# skipping test because the Seccomp feature is disabled by default on k8s cluster and must be allowed manually by the cluster admin.
test_k8s_skip_enforce_seccomp_profile_whitelist_deployment_initcontainer_pod_level_bad {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_initcontainer_pod_level_1_bad {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default", "container.seccomp.security.alpha.kubernetes.io/busybox": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_initcontainer_pod_level_2_bad {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default", "container.seccomp.security.alpha.kubernetes.io/busybox": "runtime/default"}})
	p := {"whitelist": ["docker/default"]}

	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_seccomp_profile_whitelist_deployment_initcontainer_pod_level_1_good {
	in := input_deployment_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"busybox"}, "annotations": {"container.seccomp.security.alpha.kubernetes.io/nginx": "docker/default", "container.seccomp.security.alpha.kubernetes.io/busybox": "docker/default"}})
	p := {"whitelist": ["docker/default"]}
	actual := v1.enforce_seccomp_profile_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_deny_forbidden_sysctls_without_securitycontext_good {
	p := {"forbidden_sysctls": {"net.core.somaxconn"}}
	in := input_with_deployment("nginx", "nginx")
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_sysctls_good {
	p := {"forbidden_sysctls": {"net.core.somaxconn"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "kernel.shm_rmid_forced", "value": "1"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_sysctls_bad {
	p := {"forbidden_sysctls": {"kernel.shm_rmid_forced"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.ipv4.tcp_syncookies", "value": "1"}, {"name": "kernel.shm_rmid_forced", "value": "1"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_sysctls_all_bad {
	p := {"forbidden_sysctls": {"*"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.ipv4.tcp_syncookies", "value": "1"}, {"name": "kernel.shm_rmid_forced", "value": "1"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_unsafe_sysctls_good {
	p := {"allowed_unsafe_sysctls": {"net.core.somaxconn"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.core.somaxconn", "value": "256"}, {"name": "kernel.shm_rmid_forced", "value": "1"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_unsafe_sysctls_bad {
	p := {"forbidden_sysctls": {"kernel.shm_rmid_forced"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.core.somaxconn", "value": "256"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_and_unsafe_sysctls_bad {
	p := {"forbidden_sysctls": {"kernel.shm_rmid_forced"}, "allowed_unsafe_sysctls": {"net.core.somaxconn"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.core.somaxconn", "value": "256"}, {"name": "kernel.shm_rmid_forced", "value": "1"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_and_unsafe_sysctls_good {
	p := {"forbidden_sysctls": {"kernel.shm_rmid_forced"}, "allowed_unsafe_sysctls": {"net.core.somaxconn"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.core.somaxconn", "value": "256"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# skipping test because unsafe sysctls are disabled by default and must be allowed manually by the cluster admin on a per-node basis
test_k8s_skip_deny_forbidden_unsafe_sysctls_with_unsafe_bad {
	p := {"forbidden_sysctls": {"kernel.shm_rmid_forced"}, "allowed_unsafe_sysctls": {"net.core.somaxconn"}}
	in := input_pod_controller_with_args({"kind": "Deployment", "podSecurityContext": {"sysctls": [{"name": "net.core.somaxconn", "value": "256"}, {"name": "kernel.msgmax", "value": "65536"}]}})
	actual := v1.deny_unsafe_and_forbidden_sysctls with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# MustRunAsNonRoot
test_k8s_enforce_container_mustrunasnonroot_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_podseccontext_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 0}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_without_userid_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_false_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsNonRoot": false}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_podcontext_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsNonRoot": true}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_podcontext_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsNonRoot": false}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_containercontext_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsNonRoot": true}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_containercontext_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsNonRoot": false}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_userid_0_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsUser": 0}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_userid_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_container_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "containerSecurityContext": {"runAsNonRoot": true}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_container_bad {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "containerSecurityContext": {"runAsNonRoot": false}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_replicaset_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_replicaset_bad {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "containerSecurityContext": {"runAsUser": 0}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_replicaset_container_good {
	in := input_pod_controller_with_args({"kind": "ReplicaSet", "containers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_userid_root_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsUser": 0, "runAsNonRoot": true}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_deployment_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}, "initContainerSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 0}, "initContainerSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_2_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 0}, "podSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_2_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_3_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "podSecurityContext": {"runAsUser": 150}, "containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_4_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_5_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsNonRoot": true}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_6_good {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsNonRoot": false, "runAsUser": 20}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_container_mustrunasnonroot_multiple_containers_7_bad {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsNonRoot": false}, "initContainerSecurityContext": {"runAsNonRoot": false}})
	p := {"rule": "MustRunAsNonRoot"}

	actual := v1.enforce_container_mustrunasnonroot with data.library.parameters as p
		with input as in

	count(actual) > 0
}

# MustRunAs
test_k8s_enforce_pod_runas_userid_rule_whitelist_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"user_id_ranges": ["1-200"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsUser": 150}})
	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_1_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}})
	p := {"user_id_ranges": ["1-200"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_2_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 250}})
	p := {"user_id_ranges": ["1-200"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_3_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}})
	p := {"user_id_ranges": ["1-200"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_4_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}})

	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_5_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 10}, "initContainerSecurityContext": {"runAsUser": 150}})

	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_6_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 10}, "initContainerSecurityContext": {"runAsUser": 50}})

	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_7_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsUser": 10}, "containerSecurityContext": {"runAsUser": 10}, "initContainerSecurityContext": {"runAsUser": 150}})

	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_8_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 120}, "containerSecurityContext": {"runAsUser": 150}})
	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_9_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsUser": 20}, "containerSecurityContext": {"runAsUser": 50}})
	p := {"user_id_ranges": ["1-100"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_10_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 50}, "initContainerSecurityContext": {"runAsUser": 250}})
	p := {"user_id_ranges": ["1-100", "200-300"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_userid_rule_whitelist_11_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsUser": 150}, "initContainerSecurityContext": {"runAsUser": 250}})
	p := {"user_id_ranges": ["1-100", "200-300"]}

	actual := v1.enforce_pod_runas_userid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_1_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}})
	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_2_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_3_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_4_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_5_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}})
	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_6_bad {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# groupid - container-SecurityConetxt pod
test_k8s_enforce_pod_runas_groupid_rule_whitelist_7_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_8_bad {
	in := input_pod_controller_with_args_a({"kind": "Deployment", "containers": {"nginx"}, "initcontainers": {"nginx"}, "initContainerSecurityContext": {"runAsGroup": 150}})
	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_9_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsGroup": 120}, "containerSecurityContext": {"runAsGroup": 50}})

	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_10_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsGroup": 20}, "containerSecurityContext": {"runAsGroup": 50}})

	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-200"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_11_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsGroup": 20}, "containerSecurityContext": {"runAsGroup": 50}, "initContainerSecurityContext": {"runAsGroup": 0}})

	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_12_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"runAsGroup": 20}, "containerSecurityContext": {"runAsGroup": 50}, "initContainerSecurityContext": {"runAsGroup": 0}})

	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_13_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}})

	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-100"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_14_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsGroup": 250}, "initContainerSecurityContext": {"runAsGroup": 80}})

	p := {
		"run_as_group_rule": "MayRunAs",
		"group_id_ranges": ["1-100", "200-300"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_runas_groupid_rule_whitelist_15_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"runAsGroup": 50}, "initContainerSecurityContext": {"runAsGroup": 150}})

	p := {
		"run_as_group_rule": "MustRunAs",
		"group_id_ranges": ["1-100", "200-300"],
	}

	actual := v1.enforce_pod_runas_groupid_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# seLinux Options...
input_seLinuxOptions = x {
	x := {
		"level": "s0:c123,c456",
		"role": "object_r",
		"type": "svirt_sandbox_file_t",
		"user": "system_u",
	}
}

# seLinuxOptions pod
test_k8s_enforce_selinux_options_whitelist_mustrunas_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

# seLinuxOptions pod_controller
# deployment
test_k8s_enforce_selinux_options_whitelist_mustrunas_1_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

input_seLinuxOptions_2 = x {
	x := {
		"level": "s1:c234,c567",
		"role": "object_r",
		"type": "svirt_sandbox_file_t",
		"user": "system_u",
	}
}

input_seLinuxOptions_3 = x {
	x := {
		"level": "s0:c123,c456",
		"role": "object_r",
		"type": "svirt_lxc_net_t",
		"user": "system_u",
	}
}

# seLinuxOptions pod
test_k8s_enforce_selinux_options_whitelist_mustrunas_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_without_selinux_options_whitelist_mustrunas_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

# seLinuxOptions pod
# SC present in one container, absent at other
test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_1_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 2
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_3_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_2_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_5_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_1_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_precedence_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_precedence_1_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_precedence_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_precedence_1_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_2_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "containerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}, "initContainerSecurityContext": {"seLinuxOptions": input_seLinuxOptions}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_without_selinuxoptions_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

input_seLinuxOptions_2subset = x {
	x := {
		"level": "s1:c234,c567",
		"role": "object_r",
	}
}

input_seLinuxOptions_3subset = x {
	x := {"role": "object_r"}
}

# seLinuxOptions subset testing

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2subset}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_2_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_3subset}})
	p := input_seLinuxOptions_2subset

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_3_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2subset}})
	p := input_seLinuxOptions_2

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_4_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2subset}})
	p := input_seLinuxOptions

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_2subset}})
	p := input_seLinuxOptions_2subset

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_selinux_options_whitelist_mustrunas_multiple_containers_subset_5_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}, "podSecurityContext": {"seLinuxOptions": input_seLinuxOptions_3subset}})
	p := input_seLinuxOptions_2subset

	actual := v1.enforce_selinux_options_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_prohibit_bare_pods_good {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "dapi-test-pod",
					"ownerReferences": [{
						"apiVersion": "apps/v1",
						"blockOwnerDeletion": true,
						"controller": true,
						"kind": "ReplicaSet",
						"name": "dapi-test-6557497784",
						"uid": "942040eb-7bdd-4b46-a342-e4f86c97927a",
					}],
				},
				"spec": {
					"containers": [{
						"name": "test-container",
						"image": "k8s.gcr.io/busybox",
						"command": [
							"/bin/sh",
							"-c",
							"cat /etc/config/keys",
						],
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}

	actual := v1.prohibit_bare_pods with input as in
	count(actual) == 0
}

test_k8s_prohibit_bare_pods_bad {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"namespace": "prod",
			"object": {
				"metadata": {"name": "dapi-test-pod"},
				"spec": {
					"containers": [{
						"name": "test-container",
						"image": "k8s.gcr.io/busybox",
						"command": [
							"/bin/sh",
							"-c",
							"cat /etc/config/keys",
						],
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}

	actual := v1.prohibit_bare_pods with input as in
	count(actual) == 1
}

test_k8s_deny_all_host_paths_bad {
	in := input_pod_have_host_path
	actual := v1.deny_all_host_paths with input as in
	count(actual) == 1
}

test_k8s_deny_all_host_paths_good {
	in := input_pod_does_not_have_host_path
	actual := v1.deny_all_host_paths with input as in
	count(actual) == 0
}

test_k8s_deny_all_host_paths_1_bad {
	in := input_resource_have_host_path
	actual := v1.deny_all_host_paths with input as in
	count(actual) == 1
}

test_k8s_deny_all_host_paths_1_good {
	in := input_resource_does_not_have_host_path
	actual := v1.deny_all_host_paths with input as in
	count(actual) == 0
}

input_pod_have_host_path = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "prod",
		"object": {
			"metadata": {"name": "test-pd"},
			"spec": {
				"containers": [{
					"image": "k8s.gcr.io/test-webserver",
					"name": "test-container",
					"volumeMounts": [{
						"mountPath": "/test-pd",
						"name": "test-volume",
					}],
				}],
				"volumes": [{
					"name": "test-volume",
					"hostPath": {
						"path": "/data",
						"type": "Directory",
					},
				}],
			},
		},
	},
}

input_pod_does_not_have_host_path = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "prod",
		"object": {
			"metadata": {"name": "test-pd"},
			"spec": {
				"containers": [{
					"image": "k8s.gcr.io/test-webserver",
					"name": "test-container",
					"volumeMounts": [{
						"mountPath": "/test-pd",
						"name": "test-volume",
					}],
				}],
				"volumes": [{
					"name": "test-volume",
					"secret": {"secretName": "test"},
				}],
			},
		},
	},
}

input_resource_have_host_path = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Deployment"},
		"namespace": "prod",
		"object": {"spec": {
			"selector": {"matchLabels": {"app": "nginx"}},
			"replicas": 2,
			"template": {
				"metadata": {"labels": {"app": "nginx"}},
				"spec": {
					"initContainers": [{
						"image": "opa:latest",
						"name": "opa",
						"volumeMounts": [{
							"mountPath": "/test-pd1",
							"name": "test-volume",
						}],
					}],
					"containers": [{
						"name": "foo",
						"image": "container_image",
						"volumeMounts": [{
							"mountPath": "/test-pd",
							"name": "test-volume",
						}],
					}],
					"volumes": [{
						"name": "test-volume",
						"hostPath": {
							"path": "/etc",
							"type": "Directory",
						},
					}],
				},
			},
		}},
	},
}

input_resource_does_not_have_host_path = {
	"apiVersion": "admission.k8s.io/v1beta1",
	"kind": "AdmissionReview",
	"request": {
		"userinfo": {"username": "alice"},
		"operation": "CREATE",
		"kind": {"kind": "Deployment"},
		"namespace": "prod",
		"object": {"spec": {
			"selector": {"matchLabels": {"app": "nginx"}},
			"replicas": 2,
			"template": {
				"metadata": {"labels": {"app": "nginx"}},
				"spec": {
					"initContainers": [{
						"image": "opa:latest",
						"name": "opa",
						"volumeMounts": [{
							"mountPath": "/test-pd1",
							"name": "test-volume-1",
						}],
					}],
					"containers": [{
						"name": "foo",
						"image": "container_image",
						"volumeMounts": [{
							"mountPath": "/test-pd1",
							"name": "test-volume-1",
						}],
					}],
					"volumes": [{
						"name": "test-volume-1",
						"configMap": {
							"name": "log-config",
							"items": [{
								"key": "log_level",
								"path": "log_level",
							}],
						},
					}],
				},
			},
		}},
	},
}

test_k8s_block_privileged_mode_regular_containers_pod_bad {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_regular_containers_pod_good {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"privileged": false}})
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_regular_containers_pod_with_init_container {
	in := input_with_pod_with_args_a({"initcontainers": {"nginx"}, "containers": {"nginx"}, "initContainerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_regular_containers_pod_with_no_security_context {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_regular_containers_deployment_bad {
	regular_containers := [{
		"image": "nginx:1.14.2",
		"imagePullPolicy": "IfNotPresent",
		"name": "nginx",
		"ports": [{
			"containerPort": 80,
			"protocol": "TCP",
		}],
		"resources": {},
		"securityContext": {"privileged": true},
	}]

	init_containers := [{
		"command": [
			"sh",
			"-c",
			"until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done",
		],
		"image": "busybox:1.28",
		"imagePullPolicy": "IfNotPresent",
		"name": "init-myservice",
		"resources": {},
		"securityContext": {"privileged": false},
		"terminationMessagePath": "/dev/termination-log",
		"terminationMessagePolicy": "File",
	}]

	in := input_deployment_with_regular_init_containers(regular_containers, init_containers)
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_regular_containers_deployment_good {
	regular_containers := [{
		"image": "nginx:1.14.2",
		"imagePullPolicy": "IfNotPresent",
		"name": "nginx",
		"ports": [{
			"containerPort": 80,
			"protocol": "TCP",
		}],
		"resources": {},
		"securityContext": {"privileged": false},
	}]

	init_containers := [{
		"command": [
			"sh",
			"-c",
			"until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done",
		],
		"image": "busybox:1.28",
		"imagePullPolicy": "IfNotPresent",
		"name": "init-myservice",
		"resources": {},
		"securityContext": {"privileged": false},
		"terminationMessagePath": "/dev/termination-log",
		"terminationMessagePolicy": "File",
	}]

	in := input_deployment_with_regular_init_containers(regular_containers, init_containers)
	actual := v1.block_privileged_mode_regular_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_init_containers_pod_bad {
	in := input_with_pod_with_args_a({"initcontainers": {"nginx"}, "containers": {"nginx"}, "initContainerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_init_containers_pod_good {
	in := input_with_pod_with_args_a({"initcontainers": {"nginx"}, "containers": {"nginx"}, "initContainerSecurityContext": {"privileged": false}})
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_init_containers_pod_with_regular_container {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "containerSecurityContext": {"privileged": true}})
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_init_containers_pod_with_no_security_context {
	in := input_with_pod_with_args_a({"containers": {"nginx"}, "initcontainers": {"nginx"}})
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 0
}

test_k8s_block_privileged_mode_init_containers_deployment_bad {
	regular_containers := [{
		"image": "nginx:1.14.2",
		"imagePullPolicy": "IfNotPresent",
		"name": "nginx",
		"ports": [{
			"containerPort": 80,
			"protocol": "TCP",
		}],
		"resources": {},
		"securityContext": {"privileged": false},
	}]

	init_containers := [{
		"command": [
			"sh",
			"-c",
			"until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done",
		],
		"image": "busybox:1.28",
		"imagePullPolicy": "IfNotPresent",
		"name": "init-myservice",
		"resources": {},
		"securityContext": {"privileged": true},
		"terminationMessagePath": "/dev/termination-log",
		"terminationMessagePolicy": "File",
	}]

	in := input_deployment_with_regular_init_containers(regular_containers, init_containers)
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 1
}

test_k8s_block_privileged_mode_init_containers_deployment_good {
	regular_containers := [{
		"image": "nginx:1.14.2",
		"imagePullPolicy": "IfNotPresent",
		"name": "nginx",
		"ports": [{
			"containerPort": 80,
			"protocol": "TCP",
		}],
		"resources": {},
		"securityContext": {"privileged": false},
	}]

	init_containers := [{
		"command": [
			"sh",
			"-c",
			"until nslookup myservice.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local; do echo waiting for myservice; sleep 2; done",
		],
		"image": "busybox:1.28",
		"imagePullPolicy": "IfNotPresent",
		"name": "init-myservice",
		"resources": {},
		"securityContext": {"privileged": false},
		"terminationMessagePath": "/dev/termination-log",
		"terminationMessagePolicy": "File",
	}]

	in := input_deployment_with_regular_init_containers(regular_containers, init_containers)
	actual := v1.block_privileged_mode_init_containers with input as in

	count(actual) == 0
}

input_deployment_with_regular_init_containers(regular_containers, init_containers) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"dryRun": false,
			"kind": {
				"group": "apps",
				"kind": "Deployment",
				"version": "v1",
			},
			"name": "nginx-deployment",
			"namespace": "default",
			"object": {
				"apiVersion": "apps/v1",
				"kind": "Deployment",
				"metadata": {
					"creationTimestamp": "2021-06-15T11:41:59Z",
					"generation": 1,
					"labels": {"app": "nginx"},
					"name": "nginx-deployment",
					"namespace": "default",
					"uid": "66c6372e-973a-4c0d-b51c-c6ff3bba9480",
				},
				"spec": {
					"progressDeadlineSeconds": 600,
					"replicas": 3,
					"revisionHistoryLimit": 10,
					"selector": {"matchLabels": {"app": "nginx"}},
					"strategy": {
						"rollingUpdate": {
							"maxSurge": "25%",
							"maxUnavailable": "25%",
						},
						"type": "RollingUpdate",
					},
					"template": {
						"metadata": {"labels": {"app": "nginx"}},
						"spec": {
							"containers": regular_containers,
							"initContainers": init_containers,
							"restartPolicy": "Always",
							"schedulerName": "default-scheduler",
							"securityContext": {},
							"terminationGracePeriodSeconds": 30,
						},
					},
				},
			},
		},
	}
}

test_input_all_containers {
	pod_containers := v1.input_all_container with input as input_pod_host_path
	count(pod_containers) == 1

	total_containers := v1.input_all_container with input as input_pod_host_path_with_ephemeral_container
	count(total_containers) == 2

	deployment_containers := v1.input_all_container with input as input_with_deployment("nginx", "nginx")
	count(deployment_containers) == 1

	rs_containers := v1.input_all_container with input as input_with_replica_set("foo")
	count(rs_containers) == 1

	ds_containers := v1.input_all_container with input as input_with_daemonset
	count(ds_containers) == 1

	job_containers := v1.input_all_container with input as input_job
	count(job_containers) == 1

	cronjob_containers := v1.input_all_container with input as input_cronjob
	count(cronjob_containers) == 1

	cronjob2_containers := v1.input_all_container with input as input_cronjob_with_init_container
	count(cronjob2_containers) == 2
}

test_allow_if_not_default {
	valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "nginx",
						"image": "nginx:latest",
					}],
					"serviceAccountName": "customsa",
				},
			},
		},
	}

	count(v1.deny_default_service_account) == 0 with input as valid
}

test_deny_if_default {
	invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "nginx",
						"image": "nginx:latest",
					}],
					"serviceAccountName": "default",
				},
			},
		},
	}

	count(v1.deny_default_service_account) == 1 with input as invalid
}

test_allow_if_false {
	valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "nginx",
						"image": "nginx:latest",
					}],
					"automountServiceAccountToken": false,
				},
			},
		},
	}

	count(v1.deny_service_account_token_mount) == 0 with input as valid
}

test_deny_if_not_false {
	invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "nginx",
						"image": "nginx:latest",
					}],
					"automountServiceAccountToken": true,
				},
			},
		},
	}

	count(v1.deny_service_account_token_mount) == 1 with input as invalid
}

test_deny_if_field_missing {
	invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {"containers": [{
					"name": "nginx",
					"image": "nginx:latest",
				}]},
			},
		},
	}

	count(v1.deny_service_account_token_mount) == 1 with input as invalid
}

test_k8s_deny_host_process_valid {
	host_process_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "test",
						"image": "sample:latest",
						"command": [
							"ping",
							"-t",
							"127.0.0.1",
						],
						"securityContext": {"windowsOptions": {
							"hostProcess": true,
							"runAsUserName": "NT AUTHORITY\\SYSTEM",
						}},
					}],
					"hostNetwork": true,
					"nodeSelector": {"kubernetes.io/os": "windows"},
				},
			},
		},
	}

	count(v1.deny_host_process) == 1 with input as host_process_valid
}

test_k8s_deny_host_process_invalid {
	host_process_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "test",
						"image": "sample:latest",
						"command": [
							"ping",
							"-t",
							"127.0.0.1",
						],
					}],
					"hostNetwork": true,
					"nodeSelector": {"kubernetes.io/os": "windows"},
				},
			},
		},
	}

	count(v1.deny_host_process) == 0 with input as host_process_invalid
}

test_k8s_capabilities_baseline_object_valid {
	capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {
					"securityContext": {"capabilities": {"add": [
						"NET_BIND_SERVICE",
						"AUDIT_WRITE",
						"KILL",
					]}},
					"containers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 0 with input as capabilities_valid
}

test_k8s_capabilities_baseline_container_valid {
	capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {
					"containers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
						"securityContext": {"capabilities": {"add": [
							"NET_BIND_SERVICE",
							"AUDIT_WRITE",
							"KILL",
						]}},
					}],
					"initContainers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
						"securityContext": {"capabilities": {"add": [
							"FSETID",
							"SETFCAP",
							"SETGID",
						]}},
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 0 with input as capabilities_valid
}

test_k8s_capabilities_baseline_ephemeralcontainers_valid {
	capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "my-container",
						"image": "nginx:latest",
						"securityContext": {"capabilities": {"add": "CHOWN"}},
					}],
					"ephemeralContainers": [{
						"securityContext": {"capabilities": {"add": "CHOWN"}},
						"image": "k8s.gcr.io/test-ephemeral",
						"imagePullPolicy": "IfNotPresent",
						"name": "debugger-2w64s",
						"resources": {},
						"stdin": true,
						"targetContainerName": "nginx",
						"terminationMessagePath": "/dev/termination-log",
						"terminationMessagePolicy": "File",
						"tty": true,
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 0 with input as capabilities_valid
}

test_k8s_capabilities_baseline_object_invalid {
	capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {
					"securityContext": {"capabilities": {"add": [
						"NET_ADMIN",
						"NET_RAW",
					]}},
					"containers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
						"securityContext": {"capabilities": {"add": [
							"NET_ADMIN",
							"NET_RAW",
							"WAKE_ALARM",
						]}},
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 2 with input as capabilities_invalid
}

test_k8s_capabilities_baseline_container_invalid {
	capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {
					"containers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
						"securityContext": {"capabilities": {"add": [
							"NET_BROADCAST",
							"LEASE",
							"NET_RAW",
							"KILL",
						]}},
					}],
					"initContainers": [{
						"name": "sec-ctx-4",
						"image": "gcr.io/google-samples/node-hello:1.0",
						"securityContext": {"capabilities": {"add": [
							"FSETID",
							"IPC_LOCK",
							"NET_RAW",
							"SETGID",
						]}},
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 2 with input as capabilities_invalid
}

test_k8s_capabilities_baseline_ephemeralcontainers_invalid {
	capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "my-container",
						"image": "nginx:latest",
						"securityContext": {"capabilities": {"add": [
							"NET_RAW",
							"NET_ADMIN",
						]}},
					}],
					"ephemeralContainers": [{
						"securityContext": {"capabilities": {"add": [
							"NET_RAW",
							"SETGID",
						]}},
						"image": "k8s.gcr.io/test-ephemeral",
						"imagePullPolicy": "IfNotPresent",
						"name": "debugger-2w64s",
						"resources": {},
						"stdin": true,
						"targetContainerName": "nginx",
						"terminationMessagePath": "/dev/termination-log",
						"terminationMessagePolicy": "File",
						"tty": true,
					}],
				},
			},
		},
	}

	count(v1.deny_capabilities_baseline) == 2 with input as capabilities_invalid
}

test_k8s_capabilities_not_in_blacklist {
	capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {
						"add": ["NET_BIND_SERVICE"],
						"drop": ["ALL"],
					}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 0 with input as capabilities_valid
}

test_k8s_capabilities_in_blacklist {
	capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {
						"add": ["NET_RAW"],
						"drop": ["NET_BIND_SERVICE"],
					}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 2 with input as capabilities_invalid
}

test_k8s_added_capabilities_not_in_blacklist {
	added_capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 0 with input as added_capabilities_valid
}

test_k8s_added_capabilities_in_blacklist {
	added_capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 1 with input as added_capabilities_invalid
}

test_k8s_dropped_capabilities_not_in_blacklist {
	dropped_capabilities_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {"drop": ["ALL"]}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 0 with input as dropped_capabilities_valid
}

test_k8s_dropped_capabilities_in_blacklist {
	dropped_capabilities_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "security-context-demo-4"},
				"spec": {"containers": [{
					"name": "sec-ctx-4",
					"image": "gcr.io/google-samples/node-hello:1.0",
					"securityContext": {"capabilities": {"drop": ["NET_BIND_SERVICE"]}},
				}]},
			},
		},
	}

	count(v1.deny_capabilities_restricted) == 1 with input as dropped_capabilities_invalid
}

test_k8s_seccomp_profiles_valid {
	seccomp_profiles_valid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
					"containers": [{
						"name": "my-container",
						"image": "nginx:latest",
						"securityContext": {"seccompProfile": {
							"type": "Localhost",
							"localhostProfile": "default",
						}},
					}],
				},
			},
		},
	}

	count(v1.deny_restricted_seccomp_profiles) == 0 with input as seccomp_profiles_valid
}

test_k8s_seccomp_profiles_invalid {
	seccomp_profiles_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Deployment",
				"version": "apps/v1",
			},
			"object": {
				"metadata": {
					"name": "nginx-deployment",
					"labels": {"app": "nginx"},
				},
				"spec": {
					"replicas": 3,
					"selector": {"matchLabels": {"app": "nginx"}},
					"template": {
						"metadata": {"labels": {"app": "nginx"}},
						"spec": {
							"securityContext": {"seccompProfile": {"type": "Unconfined"}},
							"containers": [{
								"name": "nginx",
								"image": "nginx:1.14.2",
								"securityContext": {"seccompProfile": {"type": "Unconfined"}},
								"ports": [{"containerPort": 80}],
							}],
							"initContainers": [{
								"name": "init-myservice",
								"image": "busybox:1.28",
								"securityContext": {"seccompProfile": {"type": "Unconfined"}},
							}],
						},
					},
				},
			},
		},
	}

	count(v1.deny_restricted_seccomp_profiles) == 3 with input as seccomp_profiles_invalid
}

test_k8s_ephemeralcontainers_seccomp_profiles_invalid {
	seccomp_profiles_invalid := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": null,
				"kind": "Pod",
				"version": "v1",
			},
			"object": {
				"metadata": {"name": "my-pod"},
				"spec": {
					"containers": [{
						"name": "my-container",
						"image": "nginx:latest",
						"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
					}],
					"ephemeralContainers": [{
						"securityContext": {"seccompProfile": {"type": "Unconfined"}},
						"image": "k8s.gcr.io/test-ephemeral",
						"imagePullPolicy": "IfNotPresent",
						"name": "debugger-2w64s",
						"resources": {},
						"stdin": true,
						"targetContainerName": "nginx",
						"terminationMessagePath": "/dev/termination-log",
						"terminationMessagePolicy": "File",
						"tty": true,
					}],
				},
			},
		},
	}

	count(v1.deny_restricted_seccomp_profiles) == 1 with input as seccomp_profiles_invalid
}

cosign_verification_parameters := {"verification_config": {
	"allow_with_verification": {
		"": {
			"nginx": {"key": "NOT-A-REAL-KEY"},
			"hooli/busybox": {"key": "NOT-A-REAL-KEY"},
		},
		"gcr.io": {"hooli/piper": {"key": "NOT-A-REAL-KEY"}},
	},
	"allow_without_verification": {
		"": ["slp"],
		"gcr.io": ["hooli/cicd"],
	},
}}

test_validate_image_signature_with_cosign_success {
	in := input_with_images({
		"containers": {
			"hooli/busybox:1.0",
			"gcr.io/hooli/piper@sha256:1dffc7fa199a5156cba6ef34db5f8aaf95d6d8593b907cd392bd813da4a04754",
		},
		"initcontainers": {"nginx:custom"},
	})
	slp_response := {
		"status_code": 200,
		"body": {"response": {"items": [{
			{"key": "gcr.io/hooli/piper", "value": "gcr.io/hooli/piper_valid"},
			{"key": "hooli/busybox", "value": "hooli/busybox_valid"},
			{"key": "nginx", "value": "nginx_valid"},
		}]}},
	}
	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
		with http.send as slp_response
		with data.library.parameters as cosign_verification_parameters
	print(actual)
	count(actual) == 0
}

test_validate_image_signature_with_cosign_skipped {
	in := input_with_images({"containers": {"gcr.io/hooli/cicd:v1.0"}, "initcontainers": {"slp:1.1"}})
	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
		with data.library.parameters as cosign_verification_parameters
	print(actual)
	count(actual) == 0
}

test_validate_image_signature_with_cosign_HTTP_non_200_response {
	in := input_with_images({"containers": {"hooli/busybox"}, "initcontainers": {"nginx"}})
	slp_response := {"status_code": 500}
	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
		with http.send as slp_response
		with data.library.parameters as cosign_verification_parameters
	count(actual) == 2
}

test_validate_image_signature_with_cosign_systemError {
	in := input_with_images({"containers": {"hooli/busybox"}, "initcontainers": {"nginx"}})
	slp_response := {
		"status_code": 200,
		"body": {"response": {"systemError": "a test system error"}},
	}
	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
		with http.send as slp_response
		with data.library.parameters as cosign_verification_parameters
	count(actual) == 2
}

test_validate_image_signature_with_cosign_item_error {
	in := input_with_images({"containers": {"hooli/busybox"}, "initcontainers": {"nginx"}})
	slp_response := {
		"status_code": 200,
		"body": {"response": {"items": [{"error": "an item error"}]}},
	}

	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
		with http.send as slp_response
		with data.library.parameters as cosign_verification_parameters
	count(actual) == 2
}

test_validate_skip_when_kubelet_initiated {
	in := input_with_images({"containers": {"hooli.com/busybox@sha256:1234"}, "userGroups": ["system:nodes"]})

	actual := v1.image_signature_verification_sigstore_cosign_v0_0_1 with input as in
	count(actual) == 0
}

test_kubelet_initiated_success {
	in := input_with_images({"containers": {"hooli.com/busybox"}, "userGroups": ["system:nodes"]})
	v1.kubelet_initiated with input as in
}

test_kubelet_initiated_fail {
	in := input_with_images({"containers": {"hooli.com/busybox"}})
	not v1.kubelet_initiated with input as in
}

test_matches_registry_success {
	v1.matches_registry("", "nginx", "nginx")
	v1.matches_registry("gcr.io", "nginx", "gcr.io/nginx")
	v1.matches_registry("", "**", "anything")
	v1.matches_registry("", "stage-*", "stage-foo")
	v1.matches_registry("gcr.io", "stage-*", "gcr.io/stage-foo")
}

test_matches_registry_fail {
	not v1.matches_registry("", "nginx", "not-nginx")
	not v1.matches_registry("gcr.io", "nginx", "gcr.io/ubuntu")
	not v1.matches_registry("", "prod-*", "stage-foo")
	not v1.matches_registry("gcr.io", "prod-*", "gcr.io/stage-foo")
}
