package library.v1.kubernetes.admission.metadata.test_v1

import data.library.v1.kubernetes.admission.metadata.v1
import data.library.v1.kubernetes.admission.test_objects.v1 as objects

test_k8s_missing_label_complete {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {"foo": "bar"}}
	in := input_with_metadata(meta)
	actual := v1.missing_label with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_missing_label_invalid_costcenter {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {
		"costcenter": "bad",
		"owner": "john",
	}}

	in := input_replica_set_with_metadata(meta)
	actual := v1.missing_label with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_missing_label_ok {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {
		"costcenter": "commercial",
		"owner": "john",
	}}

	in := input_with_metadata(meta)
	actual := v1.missing_label with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_template_pod_missing_label_complete {
	p := {"labels": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {"foo": "bar"}}
	in := input_resource_template_with_metadata(meta)
	actual := v1.template_pod_missing_label with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_template_pod_missing_label_invalid_costcenter {
	p := {"labels": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {
		"costcenter": "bad",
		"owner": "john",
		"foo": "bar",
	}}

	in := input_resource_template_with_metadata(meta)
	actual := v1.template_pod_missing_label with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_template_pod_missing_label_ok {
	p := {"labels": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {
		"costcenter": "commercial",
		"owner": "john",
		"foo": "bar",
	}}

	in := input_resource_template_with_metadata(meta)
	actual := v1.template_pod_missing_label with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_all_pods_belong_to_some_tier {
	in := objects.nginxpod({"labels": {"foo": "true", "app": "true"}})
	actual := v1.pod_fails_to_match_exactly_one_label with data.library.parameters as {"required": {"app", "data"}}
		with input as objects.admission(in)

	count(actual) == 0
}

test_k8s_all_pods_belong_to_some_tier_deny {
	in := objects.nginxpod({"labels": {"foo": "true", "bar": "true"}})
	actual := v1.pod_fails_to_match_exactly_one_label with data.library.parameters as {"required": {"app", "data"}}
		with input as objects.admission(in)

	count(actual) == 1
}

test_k8s_missing_annotation_complete {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"labels": {"foo": "bar"}}
	in := input_with_metadata(meta)
	actual := v1.missing_annotation with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_missing_annotation_invalid_costcenter {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"annotations": {
		"costcenter": "bad",
		"owner": "john",
	}}

	in := input_replica_set_with_metadata(meta)
	actual := v1.missing_annotation with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_missing_annotation_ok {
	p := {"required": {
		"costcenter": {"retail", "commercial"},
		"owner": set(),
	}}

	meta := {"annotations": {
		"costcenter": "commercial",
		"owner": "john",
	}}

	in := input_with_metadata(meta)
	actual := v1.missing_annotation with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_invalid_naming_convention_bad {
	p := {"required": {"styra-*", "styrainc-*"}}
	meta := {"name": "invalid-pod-name"}
	in := input_replica_set_with_metadata(meta)
	actual := v1.invalid_naming_convention with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_invalid_naming_convention_ok {
	p := {"required": {"styra-*", "styrainc-*"}}
	meta := {"name": "styra-opa-pod"}
	in := input_deployment_with_metadata(meta)
	actual := v1.invalid_naming_convention with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_invalid_naming_convention_namespace_bad {
	p := {"approved_names": {"styra-*", "styrainc-*"}}
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Namespace"},
			"operation": "CREATE",
			"object": {"metadata": {"name": "test"}},
		},
	}

	actual := v1.invalid_naming_convention_namespace with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_invalid_naming_convention_namespace_no_parameter {
	p := {"approved_names": {}}
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Namespace"},
			"operation": "CREATE",
			"object": {"metadata": {"name": "test"}},
		},
	}

	actual := v1.invalid_naming_convention_namespace with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_invalid_naming_convention_namespace_delete {
	p := {"approved_names": {"styra-*", "styrainc-*"}}
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Namespace"},
			"object": {"metadata": {"name": "styra-test"}},
		},
	}

	actual := v1.invalid_naming_convention_namespace with input as in
		with data.library.parameters as p

	count(actual) == 0

	q := {"approved_names": {"styra-*"}}
	inq := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "DELETE",
			"kind": {"kind": "Namespace"},
			"object": {"metadata": {"name": "styra-test"}},
		},
	}

	actualq := v1.invalid_naming_convention_namespace with input as inq
		with data.library.parameters as q

	count(actualq) == 0
}

test_k8s_invalid_naming_convention_namespace_ok {
	p := {"approved_names": {"styra-*", "styrainc-*"}}
	in := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Namespace"},
			"object": {"metadata": {"name": "styra-test"}},
		},
	}

	actual := v1.invalid_naming_convention_namespace with input as in
		with data.library.parameters as p

	count(actual) == 0
}

input_with_metadata(metadata) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {
				"kind": "Pod",
				"version": "v1",
				"group": "",
			},
			"namespace": "prod",
			"object": {
				"metadata": metadata,
				"spec": {"containers": [{
					"image": "nginx",
					"imagePullPolicy": "Always",
					"name": "nginx",
					"securityContext": {"privileged": true},
				}]},
			},
		},
	}
}

input_replica_set_with_metadata(metadata) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "ReplicaSet"},
			"object": {
				"spec": {
					"template": {
						"spec": {"containers": [{
							"terminationMessagePath": "/dev/termination-log",
							"name": "php-redis",
							"image": "gcr.io/google_samples/gb-frontend:v3",
							"terminationMessagePolicy": "File",
							"env": [{
								"name": "GET_HOSTS_FROM",
								"value": "dns",
							}],
							"imagePullPolicy": "IfNotPresent",
							"ports": [{
								"protocol": "TCP",
								"containerPort": 80,
							}],
							"resources": {"requests": {
								"cpu": "100m",
								"memory": "100Mi",
							}},
						}]},
						"metadata": {"labels": {"costcenter": "bad"}},
					},
					"selector": {"matchLabels": {"costcenter": "bad"}},
					"replicas": 3,
				},
				"metadata": metadata,
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
	}
}

input_deployment_with_metadata(metadata) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Deployment"},
			"object": {
				"spec": {
					"template": {
						"spec": {
							"containers": [{
								"terminationMessagePath": "/dev/termination-log",
								"name": "nginx",
								"image": "nginx",
								"terminationMessagePolicy": "File",
								"ports": [{
									"protocol": "TCP",
									"containerPort": 80,
								}],
								"resources": {},
							}],
							"nodeSelector": {"disktype": "ssd"},
							"tolerations": [{
								"key": "node-role.kubernetes.io/master",
								"operator": "Exists",
							}],
						},
						"metadata": {"labels": {"costcenter": "bad"}},
					},
					"selector": {"matchLabels": {"costcenter": "bad"}},
					"replicas": 3,
				},
				"metadata": metadata,
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_resource_template_with_metadata(metadata) = x {
	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "Deployment"},
			"object": {
				"spec": {
					"template": {
						"spec": {
							"containers": [{
								"terminationMessagePath": "/dev/termination-log",
								"name": "nginx",
								"image": "nginx",
								"terminationMessagePolicy": "File",
								"ports": [{
									"protocol": "TCP",
									"containerPort": 80,
								}],
								"resources": {},
							}],
							"nodeSelector": {"disktype": "ssd"},
							"tolerations": [{
								"key": "node-role.kubernetes.io/master",
								"operator": "Exists",
							}],
						},
						"metadata": metadata,
					},
					"selector": {"matchLabels": {"foo": "bar"}},
					"replicas": 3,
				},
				"metadata": {"labels": {"costcenter": "bad"}},
			},
			"namespace": "prod",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

test_k8s_deny_nginx_ingress_configmap_with_snippet_annotation_enabled_good {
	object := {
		"apiVersion": "v1",
		"data": {
			"allow-snippet-annotations": "false",
			"enable-access-log-for-default-backend": "false",
			"enable-modsecurity": "false",
		},
		"kind": "ConfigMap",
		"metadata": {
			"labels": {
				"app.kubernetes.io/component": "controller",
				"app.kubernetes.io/instance": "ingress-nginx",
				"app.kubernetes.io/name": "ingress-nginx",
				"app.kubernetes.io/version": "1.0.4",
			},
			"name": "ingress-nginx-controller",
			"namespace": "ingress-nginx",
		},
	}

	in := input_nginx_ingress_configmap(object)
	actual := v1.deny_nginx_ingress_configmap_with_snippet_annotation_enabled with input as in
	count(actual) == 0
}

test_k8s_deny_nginx_ingress_configmap_with_snippet_annotation_enabled_bad_1 {
	object := {
		"apiVersion": "v1",
		"data": {
			"allow-snippet-annotations": "true",
			"enable-access-log-for-default-backend": "false",
			"enable-modsecurity": "false",
		},
		"kind": "ConfigMap",
		"metadata": {
			"labels": {
				"app.kubernetes.io/component": "controller",
				"app.kubernetes.io/instance": "ingress-nginx",
				"app.kubernetes.io/name": "ingress-nginx",
				"app.kubernetes.io/version": "1.0.4",
			},
			"name": "ingress-nginx-controller",
			"namespace": "ingress-nginx",
		},
	}

	in := input_nginx_ingress_configmap(object)
	actual := v1.deny_nginx_ingress_configmap_with_snippet_annotation_enabled with input as in
	count(actual) == 1
}

test_k8s_deny_nginx_ingress_configmap_with_snippet_annotation_enabled_missing_snippet {
	object := {
		"apiVersion": "v1",
		"data": {
			"enable-access-log-for-default-backend": "false",
			"enable-modsecurity": "false",
		},
		"kind": "ConfigMap",
		"metadata": {
			"labels": {
				"app.kubernetes.io/component": "controller",
				"app.kubernetes.io/instance": "ingress-nginx",
				"app.kubernetes.io/name": "ingress-nginx",
				"app.kubernetes.io/version": "1.0.4",
			},
			"name": "ingress-nginx-controller",
			"namespace": "ingress-nginx",
		},
	}

	in := input_nginx_ingress_configmap(object)
	actual := v1.deny_nginx_ingress_configmap_with_snippet_annotation_enabled with input as in
	count(actual) == 1
}

input_nginx_ingress_configmap(object) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"dryRun": false,
			"kind": {
				"group": "",
				"kind": "ConfigMap",
				"version": "v1",
			},
			"name": "ingress-nginx-controller",
			"namespace": "ingress-nginx",
			"object": object,
		},
	}
}
