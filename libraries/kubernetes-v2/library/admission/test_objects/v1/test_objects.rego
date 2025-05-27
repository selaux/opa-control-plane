package library.v1.kubernetes.admission.test_objects.v1

import data.library.v1.kubernetes.admission.util.v1 as util

# Convert a regular object into an admission control request
admission(obj) = admission_op(obj, {})

admission_op(obj, params) = x {
	smallobj := util.reduce_object_blacklist(obj, {"apiVersion"})
	op := util.get(params, "operation", "CREATE")
	x := {
		"apiVersion": "v1",
		"request": {
			"kind": {"kind": util.get(obj, "kind", "Pod")},
			"operation": op,
			"namespace": util.get(util.get(obj, "metadata", {}), "namespace", "default"),
			"object": smallobj,
		},
	}
}

nginxpod(params) = x {
	namespace := util.get(params, "namespace", "default")
	labels := util.get(params, "labels", {})
	name := util.get(params, "name", "frontend")
	image := util.get(params, "image", "ngnix")
	imagePullPolicy := util.get(params, "imagePullPolicy", "")
	resourceLimits := util.get(params, "resourceLimits", {})
	x := {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": name,
			"namespace": namespace,
			"labels": labels,
		},
		"spec": {"containers": [container(image, "nginx", imagePullPolicy, resourceLimits)]},
	}
}

nginx_uber(params) = x {
	namespace := util.get(params, "namespace", "default")
	labels := util.get(params, "labels", {})
	name := util.get(params, "name", "frontend")
	kind := util.get(params, "kind", "Deployment")
	permitted_kinds := {"Deployment", "ReplicaSet"}
	permitted_kinds[kind]
	image := util.get(params, "image", "ngnix")
	imagePullPolicy := util.get(params, "imagePullPolicy", "")
	resourceLimits := util.get(params, "resourceLimits", {})
	x := {
		"apiVersion": "apps/v1",
		"kind": kind,
		"metadata": {
			"name": name,
			"namespace": namespace,
			"labels": labels,
		},
		"spec": {
			"replicas": 2,
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {"labels": util.merge_objects({"app": "nginx"}, labels)},
				"spec": {"containers": [container(image, "nginx", imagePullPolicy, resourceLimits)]},
			},
		},
	}
}

nginx_statefulset(params) = x {
	namespace := util.get(params, "namespace", "default")
	labels := util.get(params, "labels", {})
	name := util.get(params, "name", "frontend")
	image := util.get(params, "image", "ngnix")
	imagePullPolicy := util.get(params, "imagePullPolicy", "")
	resourceLimits := util.get(params, "resourceLimits", {})
	x := {
		"apiVersion": "apps/v1",
		"kind": "StatefulSet",
		"metadata": {
			"name": name,
			"namespace": namespace,
			"labels": labels,
		},
		"spec": {
			"replicas": 2,
			"serviceName": "nginx",
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {"labels": util.merge_objects({"app": "nginx"}, labels)},
				"spec": {"containers": [container(image, "nginx", imagePullPolicy, resourceLimits)]},
			},
		},
	}
}

nginx_daemonset(params) = x {
	namespace := util.get(params, "namespace", "default")
	labels := util.get(params, "labels", {})
	name := util.get(params, "name", "frontend")
	image := util.get(params, "image", "ngnix")
	imagePullPolicy := util.get(params, "imagePullPolicy", "")
	resourceLimits := util.get(params, "resourceLimits", {})
	x := {
		"apiVersion": "apps/v1",
		"kind": "DaemonSet",
		"metadata": {
			"name": name,
			"namespace": namespace,
			"labels": labels,
		},
		"spec": {
			"selector": {"matchLabels": {"app": "nginx"}},
			"template": {
				"metadata": {"labels": util.merge_objects({"app": "nginx"}, labels)},
				"spec": {"containers": [container(image, "nginx", imagePullPolicy, resourceLimits)]},
			},
		},
	}
}

container(image, name, imagePullPolicy, resourceLimits) = x {
	imagePullPolicy == ""
	x = {"image": image, "name": name, "resources": {"limits": resourceLimits}}
}

container(image, name, imagePullPolicy, resourceLimits) = x {
	imagePullPolicy != ""
	x = {"image": image, "name": name, "imagePullPolicy": imagePullPolicy, "resources": {"limits": resourceLimits}}
}

input_with_service(type, loadBalancerSourceRanges) = x {
	x := {
		"request": {
			"kind": {"kind": "Service"},
			"object": {
				"spec": {
					"selector": {"app": "MyApp"},
					"type": type,
					"ports": [{"protocol": "TCP", "port": 8765, "targetPort": 9376}],
					"loadBalancerSourceRanges": loadBalancerSourceRanges,
				},
				"metadata": {"name": "my-service"},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}
