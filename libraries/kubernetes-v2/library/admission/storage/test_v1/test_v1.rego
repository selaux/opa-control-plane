package library.v1.kubernetes.admission.storage.test_v1

import data.library.v1.kubernetes.admission.storage.v1

test_k8s_allowed_storage_class_good {
	in := input_with_pvc("standard", "ReadWriteOnce", "10Gi", "default")
	p := {"classes": {"standard": set(), "": {"ReadOnlyMany"}}}

	actual := v1.deny_storage_class_access_mode_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_storage_class_access_mode_not_in_whitelist_good {
	in := input_with_pvc("gke", "ReadOnlyMany", "10Gi", "default")
	p := {"classes": {"standard": {"ReadWriteOnce"}, "gke": {"ReadOnlyMany"}}}

	actual := v1.deny_storage_class_access_mode_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_storage_class_access_mode_not_in_whitelist_empty_bad {
	in := input_with_pvc("gke", "ReadWriteOnce", "10Gi", "default")
	p := {"classes": {"standard": set()}}

	actual := v1.deny_storage_class_access_mode_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_allowed_storage_class_bad {
	in := input_with_pvc("gke", "ReadWriteOnce", "10Gi", "default")
	p := {"classes": {"standard": {"ReadWriteOnce"}}}

	actual := v1.deny_storage_class_access_mode_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_storage_class_access_mode_not_in_whitelist_bad {
	in := input_with_pvc("standard", "ReadOnlyMany", "10Gi", "default")
	p := {"classes": {"standard": {"ReadWriteOnce"}}}

	actual := v1.deny_storage_class_access_mode_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

# TODO: context-awareness
test_encrypted_good {
	in := input_with_pvc("standard", "ReadWriteOnce", "10Gi", "default")
	r := storage_class_resource("standard", "true")

	actual := v1.enforce_encrypt with input as in
		with data.kubernetes.resources as r

	count(actual) == 0
}

# TODO: context-awareness
test_k8s_skip_encrypted_bad {
	in := input_with_pvc("standard", "ReadWriteOnce", "10Gi", "default")
	r := storage_class_resource("standard", "false")

	actual := v1.enforce_encrypt with input as in
		with data.kubernetes.resources as r

	count(actual) == 1
}

input_with_pvc(class, mode, size, namespace) = x {
	x := {
		"request": {
			"kind": {"kind": "PersistentVolumeClaim"},
			"object": {
				"spec": {
					"accessModes": [mode], # "ReadWriteOnce", "ReadOnlyMany", "ReadWriteMany"
					"resources": {"requests": {"storage": size}},
					"storageClassName": class,
				},
				"metadata": {
					"name": "my-service",
					"namespace": namespace,
				},
			},
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

nfs_pv(class, path) = x {
	x := {
		"apiVersion": "v1",
		"kind": "PersistentVolume",
		"metadata": {"name": "test-volume"},
		"spec": {
			"capacity": {"storage": "5Gi"},
			"volumeMode": "Filesystem",
			"accessModes": ["ReadWriteOnce"],
			"persistentVolumeReclaimPolicy": "Recycle",
			"storageClassName": class,
			"nfs": {
				"path": path,
				"server": "server.host",
			},
		},
	}
}

storage_class_resource(class_name, encryption) = x {
	# work-around to help opa infer the type of class_name, see
	# https://github.com/open-policy-agent/opa/issues/1361
	valid_class_names[class_name]
	x := {"storageclasses": {class_name: {
		"apiVersion": "storage.k8s.io/v1beta1",
		"kind": "StorageClass",
		"metadata": {
			"annotations": {"storageclass.beta.kubernetes.io/is-default-class": "true"},
			"labels": {
				"addonmanager.kubernetes.io/mode": "EnsureExists",
				"kubernetes.io/cluster-service": "true",
			},
			"name": "standard",
			"resourceVersion": "276",
			"selfLink": "/apis/storage.k8s.io/v1beta1/storageclasses/standard",
			"uid": "13974b25-363f-11e9-aa70-42010a8000a5",
		},
		"parameters": {
			"type": "pd-standard",
			"encrypted": encryption,
		},
		"provisioner": "kubernetes.io/gce-pd",
		"reclaimPolicy": "Delete",
		"volumeBindingMode": "Immediate",
	}}}
}

valid_class_names["standard"]

test_enforce_nfs_mount_point_whitelist_pod_denied_no_matching_ns {
	parameters := {"approved_mount_points": {
		"test_ns": {"/this/path/ok", "so/is/this/path"},
		"other_ns": {},
	}}

	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"namespace": "prod",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {
					"name": "dapi-test-pod",
					"namespace": "prod",
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
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": [{
						"name": "config-volume",
						"nfs": {"path": "bad/path", "server": "some_server"},
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as parameters

	count(message) == 1
}

test_enforce_nfs_mount_point_whitelist_pod_denied {
	parameters := {"approved_mount_points": {
		"test_ns": {"/this/path/ok", "so/is/this/path"},
		"other_ns": {},
	}}

	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"namespace": "prod",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {
					"name": "dapi-test-pod",
					"namespace": "test_ns",
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
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": [{
						"name": "config-volume",
						"nfs": {"path": "/bad/path", "server": "theserver"},
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as parameters

	count(message) == 1
}

test_enforce_nfs_mount_point_whitelist_pod_allowed {
	parameters := {"approved_mount_points": {
		"test_ns": {"/this/path/ok", "so/is/this/path"},
		"other_ns": {},
	}}

	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {
					"name": "dapi-test-pod",
					"namespace": "test_ns",
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
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": [{
						"name": "config-volume",
						"nfs": {
							"server": "nfs-server",
							"path": "/this/path/ok",
						},
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as parameters

	count(message) == 0
}

test_enforce_nfs_mount_point_whitelist_pv_allowed {
	parameters := {"approved_mount_points": {
		"test_ns": {"/this/path/ok", "so/is/this/path"},
		"other_ns": {},
	}}

	resources := {"persistentvolumes": {"id": nfs_pv("pv-class", "/this/path/ok")}}

	in := input_with_pvc("pv-class", "ReadOnlyMany", "10Gi", "test_ns")

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.kubernetes.resources as resources with data.library.parameters as parameters

	count(message) == 0
}

test_enforce_nfs_mount_point_whitelist_pvc {
	parameters := {"approved_mount_points": {
		"test_ns": {"/this/path/ok", "so/is/this/path"},
		"other_ns": {},
	}}

	resources := {"persistentvolumes": {"id": nfs_pv("pv-class", "/bad/path")}}

	in := input_with_pvc("pv-class", "ReadOnlyMany", "10Gi", "namespace-not-specified")

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.kubernetes.resources as resources with data.library.parameters as parameters

	count(message) == 0
}

test_enforce_nfs_mount_point_whitelist_pvc_mount_point_autogenerated {
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": "",
				"kind": "PersistentVolumeClaim",
				"version": "v1",
			},
			"namespace": "trident",
			"object": {
				"metadata": {
					"name": "test-storage-foo",
					"namespace": "trident",
					"uid": "6cef78ff-a4eb-11ea-84e1-32d90070022d",
				},
				"spec": {
					"accessModes": ["ReadWriteOnce"],
					"resources": {"requests": {"storage": "5G"}},
					"storageClassName": "test-storage-class",
				},
				"status": {},
			},
			"operation": "CREATE",
			"resource": {
				"group": "",
				"resource": "persistentvolumeclaims",
				"version": "v1",
			},
		},
	}

	parameters := {"approved_mount_points": {"trident": {}}}

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as parameters

	count(message) == 0
}

test_nfs_mount_deployment_denials {
	server := "nfs-test-server"
	path := "/good/path"

	in := input_with_deployment_with_nfs_volumes([server], [path])

	misconfigured_parameters := {"approved_mount_points": {"prod": {"/good/path"}}}

	message_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as misconfigured_parameters
	count(message_misconfigured) == 1

	wrong_server_parameters := {"approved_mount_points": {"prod": {"other-server:/good/path"}}}

	wrong_server_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as wrong_server_parameters
	count(wrong_server_misconfigured) == 1

	wrong_path_parameters := {"approved_mount_points": {"prod": {"nfs-test-server:/bad/path"}}}

	wrong_path_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as wrong_path_parameters
	count(wrong_path_misconfigured) == 1
}

test_nfs_multiple_mounts_deployment_denials {
	# same tests as test_nfs_mount_deployment_denials, except with multiple volumes. Expect an error per violating volume

	servers := ["nfs-test-server", "second-test-server", "third-test-server"]
	paths := ["/good/path", "/second/path", "/another/path"]

	in := input_with_deployment_with_nfs_volumes(servers, paths)

	misconfigured_parameters := {"approved_mount_points": {"prod": {"/good/path"}}}

	message_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as misconfigured_parameters
	count(message_misconfigured) == 3

	wrong_server_parameters := {"approved_mount_points": {"prod": {"other-server:/good/path"}}}

	wrong_server_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as wrong_server_parameters
	count(wrong_server_misconfigured) == 3

	wrong_path_parameters := {"approved_mount_points": {"prod": {"nfs-test-server:/second/path"}}}

	wrong_path_misconfigured := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as wrong_path_parameters
	count(wrong_path_misconfigured) == 3

	# one violating volume mount, the other two are whitelisted, should return one error for the single violation

	two_ok_one_bad_parameters := {"approved_mount_points": {"prod": {"nfs-test-server:/good/path", "second-test-server:/second/path"}}}

	message_two_ok_one_bad := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as two_ok_one_bad_parameters
	count(message_two_ok_one_bad) == 1
}

test_nfs_mount_deployment_allow {
	server := "nfs-test-server"
	path := "/good/path"

	in := input_with_deployment_with_nfs_volumes([server], [path])

	parameters := {"approved_mount_points": {"prod": {
		"other-server:/good/path",
		"nfs-test-server:/other/path",
		"nfs-test-server:/good/path",
	}}}

	message := v1.enforce_nfs_mount_point_whitelist with input as in with data.library.parameters as parameters
	count(message) == 0
}

test_k8s_enforce_pod_flex_volume_drivers_bad {
	in := input_with_pod_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {"example/cifs"}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_flex_volume_drivers_good {
	in := input_with_pod_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {
		"example/lvm",
		"example/cifs",
	}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_flex_volume_drivers_deployment_bad {
	in := input_with_deployment_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {"example/cifs"}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_flex_volume_drivers_deployment_good {
	in := input_with_deployment_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {
		"example/lvm",
		"example/cifs",
	}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_flex_volume_drivers_replicaset_bad {
	in := input_with_replicaset_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {"example/cifs"}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_flex_volume_drivers_replicaset_good {
	in := input_with_replicaset_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {
		"example/lvm",
		"example/cifs",
	}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_flex_volume_drivers_with_volume_with_empty_whitelist_good {
	in := input_with_replicaset_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_flex_volume_drivers_deployment_with_whitelist_wildcard_good {
	in := input_with_deployment_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {"*"}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

input_with_deployment_with_flexvolume(container_name, container_image) = x {
	x := {
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
						"containers": [{
							"name": container_name,
							"image": container_image,
							"volumeMounts": [{
								"name": "config-volume",
								"mountPath": "/etc/config",
							}],
						}],
						"volumes": input_with_volumeFlex,
					},
				},
			}},
		},
	}
}

input_with_deployment_without_volume(container_name, container_image) = x {
	x := {
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
					"spec": {"containers": [{
						"name": container_name,
						"image": container_image,
					}]},
				},
			}},
		},
	}
}

input_with_replicaset_with_flexvolume(container_name, container_image) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "ReplicaSet"},
			"namespace": "prod",
			"object": {"spec": {
				"selector": {"matchLabels": {"app": "nginx"}},
				"replicas": 2,
				"template": {
					"metadata": {"labels": {"app": "nginx"}},
					"spec": {
						"containers": [{
							"name": container_name,
							"image": container_image,
							"volumeMounts": [{
								"name": "config-volume",
								"mountPath": "/etc/config",
							}],
						}],
						"volumes": input_with_volumeFlex,
					},
				},
			}},
		},
	}
}

input_with_pod_with_flexvolume(container_name, container_image) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "dapi-test-pod"},
				"spec": {
					"containers": [{
						"name": container_name,
						"image": container_image,
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": input_with_volumeFlex,
					"restartPolicy": "Never",
				},
			},
		},
	}
}

test_k8s_enforce_pod_flex_volume_drivers_deployment_good {
	in := input_with_deployment_with_flexvolume("nginx", "nginx")
	p := {"whitelist": {
		"example/lvm",
		"example/cifs",
	}}

	actual := v1.enforce_pod_flex_volume_drivers_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

input_with_volumeFlex = x {
	x := [{
		"name": "config-volume",
		"flexVolume": {"driver": "example/lvm"},
	}]
}

test_k8s_enforce_pod_volume_type_bad {
	in := input_with_pod("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
		"projected",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_volume_type_good {
	in := input_with_pod("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
		"hostPath",
		"projected",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_deployment_bad {
	in := input_with_deployment("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_volume_type_deployment_good {
	in := input_with_deployment("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
		"hostPath",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_replicaset_bad {
	in := input_with_replicaset("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 1
}

test_k8s_enforce_pod_volume_type_replicaset_good {
	in := input_with_replicaset("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
		"hostPath",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_without_volume_with_empty_whitelist_good {
	in := input_with_deployment_without_volume("nginx", "nginx")
	p := {"whitelist": {}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_without_volume_with_whitelist_good {
	in := input_with_deployment_without_volume("nginx", "nginx")
	p := {"whitelist": {
		"configMap",
		"secret",
	}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_with_volume_with_empty_whitelist_good {
	in := input_with_replicaset("nginx", "nginx")
	p := {"whitelist": {}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_volume_type_deployment_with_whitelist_wildcard_good {
	in := input_with_deployment("nginx", "nginx")
	p := {"whitelist": {"*"}}

	actual := v1.enforce_pod_volume_type_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

input_with_deployment(container_name, container_image) = x {
	x := {
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
						"containers": [{
							"name": container_name,
							"image": container_image,
							"volumeMounts": [{
								"name": "config-volume",
								"mountPath": "/etc/config",
							}],
						}],
						"volumes": [{
							"name": "config-volume",
							"hostPath": {"path": "/data", "type": "Directory"},
						}],
					},
				},
			}},
		},
	}
}

input_with_deployment_with_nfs_volumes(nfs_servers, nfs_paths) = x {
	volumesAndMounts := input_nfs_volumes(nfs_servers, nfs_paths)

	x := {
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
						"containers": [{
							"name": "nginx",
							"image": "nginx",
							"volumeMounts": volumesAndMounts.volumeMounts,
						}],
						"volumes": volumesAndMounts.volumes,
					},
				},
			}},
		},
	}
}

input_nfs_volumes(nfs_servers, nfs_paths) = x {
	volumeMounts := [m | m := {
		"name": sprintf("mount-%s-%s", [nfs_servers[i], nfs_paths[i]]),
		"mountPath": "/etc/config",
	}]

	volumes := [v | v := {
		"name": sprintf("mount-%s-%s", [nfs_servers[i], nfs_paths[i]]),
		"nfs": {
			"server": nfs_servers[i],
			"path": nfs_paths[i],
		},
	}]

	x := {
		"volumeMounts": volumeMounts,
		"volumes": volumes,
	}
}

input_with_deployment_without_volume(container_name, container_image) = x {
	x := {
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
					"spec": {"containers": [{
						"name": container_name,
						"image": container_image,
					}]},
				},
			}},
		},
	}
}

input_with_replicaset(container_name, container_image) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "ReplicaSet"},
			"namespace": "prod",
			"object": {"spec": {
				"selector": {"matchLabels": {"app": "nginx"}},
				"replicas": 2,
				"template": {
					"metadata": {"labels": {"app": "nginx"}},
					"spec": {
						"containers": [{
							"name": container_name,
							"image": container_image,
							"volumeMounts": [{
								"name": "config-volume",
								"mountPath": "/etc/config",
							}],
						}],
						"volumes": [{
							"name": "config-volume",
							"hostPath": {"path": "/data", "type": "Directory"},
						}],
					},
				},
			}},
		},
	}
}

input_with_pod(container_name, container_image) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "Pod"},
			"object": {
				"metadata": {"name": "dapi-test-pod"},
				"spec": {
					"containers": [{
						"name": container_name,
						"image": container_image,
						"volumeMounts": [{
							"name": "config-volume",
							"mountPath": "/etc/config",
						}],
					}],
					"volumes": [{
						"name": "config-volume",
						"hostPath": {"path": "/data", "type": "Directory"},
					}],
					"restartPolicy": "Never",
				},
			},
		},
	}
}

input_pod_with_args(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	init_privileged := get(args, "init_privileged", false)
	regular_privileged := get(args, "regular_privileged", false)
	regular_allow_privilege_escalation := get(args, "regular_allow_privilege_escalation", false)
	regular_root_read_only := get(args, "regular_root_read_only", false)
	init_root_read_only := get(args, "init_root_read_only", false)
	init_allow_privilege_escalation := get(args, "init_allow_privilege_escalation", false)
	name := get(args, "name", "foo")
	podSecurityContext := get(args, "podSecurityContext", {})

	containerSecurityContext := {
		"readOnlyRootFilesystem": init_root_read_only,
		"privileged": init_privileged,
		"allowPrivilegeEscalation": init_allow_privilege_escalation,
	}

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
					"securityContext": podSecurityContext,
				},
			},
		},
	}
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

	containerSecurityContext := {
		"readOnlyRootFilesystem": init_root_read_only,
		"privileged": init_privileged,
		"allowPrivilegeEscalation": init_allow_privilege_escalation,
	}

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

get(args, key, default_value) = x {
	x := args[key]
}

get(args, key, default_value) = default_value {
	not args[key]
}

# fsGroup pod
test_k8s_enforce_pod_fsgroup_rule_whitelist_mayrunas_good {
	in := input_pod_with_args({"containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_fsgroup_rule_whitelist_mustrunas_good {
	in := input_pod_with_args({"containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_without_fsgroup_rule_whitelist_mayrunas_good {
	in := input_pod_with_args({"containers": {"nginx"}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_fsgroup_rule_whitelist_mayrunas_bad {
	in := input_pod_with_args({"containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-1000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_fsgroup_rule_whitelist_mustrunas_bad {
	in := input_pod_with_args({"containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-1000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_pod_without_fsgroup_rule_whitelist_mustrunas_bad {
	in := input_pod_with_args({"containers": {"nginx"}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) >= 1
}

# fsGroup deployment
test_k8s_enforce_deployment_fsgroup_rule_whitelist_mayrunas_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_deployment_fsgroup_rule_whitelist_mustrunas_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_deployment_without_fsgroup_rule_whitelist_mayrunas_good {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_deployment_fsgroup_rule_whitelist_mayrunas_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MayRunAs",
		"fs_group_ranges": ["1-500", "501-1000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_deployment_fsgroup_rule_whitelist_mustrunas_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}, "podSecurityContext": {"fsGroup": 1500}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-500", "501-1000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) > 0
}

test_k8s_enforce_deployment_without_fsgroup_rule_whitelist_mustrunas_bad {
	in := input_pod_controller_with_args({"kind": "Deployment", "containers": {"nginx"}})
	p := {
		"fs_group_rule": "MustRunAs",
		"fs_group_ranges": ["1-2000"],
	}

	actual := v1.enforce_pod_fsgroup_rule_whitelist with data.library.parameters as p
		with input as in

	count(actual) >= 1
}
