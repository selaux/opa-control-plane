package library.v1.kubernetes.mutating.test_v1

import data.library.v1.kubernetes.admission.test_objects.v1 as objects
import data.library.v1.kubernetes.mutating.v1 as mutating
import data.library.v1.kubernetes.utils.envoy.v1 as envoy_utils
import data.library.v1.kubernetes.utils.opa.v1 as opa_utils

# ------------------------------------------------------------------------------
# Inject label(s) if missing

test_add_missing_labels_add {
	count(add_missing_labels_add) == 1
	add_missing_labels_add[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'env' to 'prod'",
		"patch": [{
			"op": "add",
			"path": "/metadata/labels/env",
			"value": "prod",
		}],
	}
}

test_add_missing_labels_add_escape_slash {
	count(add_missing_labels_add_escape_slash) == 1
	add_missing_labels_add_escape_slash[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'env/slash' to 'prod'",
		"patch": [{
			"op": "add",
			"path": "/metadata/labels/env~1slash",
			"value": "prod",
		}],
	}
}

test_add_missing_labels_nop {
	count(add_missing_labels_nop) == 0
}

# add_missing_labels_add properly adds a label which does not already exist.
add_missing_labels_add = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "bar"}})
	x := mutating.add_missing_labels with data.library.parameters as {"labels": {"env": "prod"}}
		with input as objects.admission(obj)
}

# add_missing_labels_nop attempts to add a label which already exists, thus nop.
add_missing_labels_nop = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "bar"}})
	x := mutating.add_missing_labels with data.library.parameters as {"labels": {"foo": "bar"}}
		with input as objects.admission(obj)
}

# add_missing_labels_add_ properly adds a label which does not already exist.
add_missing_labels_add_escape_slash = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "bar"}})
	x := mutating.add_missing_labels with data.library.parameters as {"labels": {"env/slash": "prod"}}
		with input as objects.admission(obj)
}

# ------------------------------------------------------------------------------
# Always pull images if latest

test_set_image_pull_policy_always_if_latest_add_pod {
	count(set_image_pull_policy_always_if_latest_add_pod) == 1
	set_image_pull_policy_always_if_latest_add_pod[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Pod/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "add",
			"path": "/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_add_deployment {
	count(set_image_pull_policy_always_if_latest_add_deployment) == 1
	set_image_pull_policy_always_if_latest_add_deployment[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Deployment/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_add_daemonset {
	count(set_image_pull_policy_always_if_latest_add_daemonset) == 1
	set_image_pull_policy_always_if_latest_add_daemonset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource DaemonSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_add_replicaset {
	count(set_image_pull_policy_always_if_latest_add_replicaset) == 1
	set_image_pull_policy_always_if_latest_add_replicaset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource ReplicaSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_add_statefulset {
	count(set_image_pull_policy_always_if_latest_add_statefulset) == 1
	set_image_pull_policy_always_if_latest_add_statefulset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource StatefulSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_replace_pod {
	count(set_image_pull_policy_always_if_latest_replace_pod) == 1
	set_image_pull_policy_always_if_latest_replace_pod[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Pod/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "replace",
			"path": "/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_replace_deployment {
	count(set_image_pull_policy_always_if_latest_replace_deployment) == 1
	set_image_pull_policy_always_if_latest_replace_deployment[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Deployment/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "replace",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_replace_daemonset {
	count(set_image_pull_policy_always_if_latest_replace_daemonset) == 1
	set_image_pull_policy_always_if_latest_replace_daemonset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource DaemonSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "replace",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_replace_replicaset {
	count(set_image_pull_policy_always_if_latest_replace_replicaset) == 1
	set_image_pull_policy_always_if_latest_replace_replicaset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource ReplicaSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "replace",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_replace_statefulset {
	count(set_image_pull_policy_always_if_latest_replace_statefulset) == 1
	set_image_pull_policy_always_if_latest_replace_statefulset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource StatefulSet/default/frontend on container nginx's image pull policy to Always",
		"patch": [{
			"op": "replace",
			"path": "/spec/template/spec/containers/0/imagePullPolicy",
			"value": "Always",
		}],
	}
}

test_set_image_pull_policy_always_if_latest_nop_pod {
	count(set_image_pull_policy_always_if_latest_nop_pod) == 0
}

test_set_image_pull_policy_always_if_latest_nop_deployment {
	count(set_image_pull_policy_always_if_latest_nop_deployment) == 0
}

test_set_image_pull_policy_always_if_latest_nop_daemonset {
	count(set_image_pull_policy_always_if_latest_nop_daemonset) == 0
}

test_set_image_pull_policy_always_if_latest_nop_replicaset {
	count(set_image_pull_policy_always_if_latest_nop_replicaset) == 0
}

test_set_image_pull_policy_always_if_latest_nop_statefulset {
	count(set_image_pull_policy_always_if_latest_nop_statefulset) == 0
}

# set_image_pull_policy_always_if_latest_add_{pod,deployment,daemonset,replicaset,statefulset} properly adds imagePullPolicy with value 'Always'.
set_image_pull_policy_always_if_latest_add_pod = x {
	obj := objects.nginxpod({"image": "nginx:latest"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_add_deployment = x {
	obj := objects.nginx_uber({"image": "nginx:latest", "kind": "Deployment"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_add_daemonset = x {
	obj := objects.nginx_daemonset({"image": "nginx:latest"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_add_replicaset = x {
	obj := objects.nginx_uber({"image": "nginx:latest", "kind": "ReplicaSet"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_add_statefulset = x {
	obj := objects.nginx_statefulset({"image": "nginx:latest"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

# set_image_pull_policy_always_if_latest_replace_{pod,deployment,daemonset,replicaset,statefulset} properly replaces imagePullPolicy with value 'Always'.
set_image_pull_policy_always_if_latest_replace_pod = x {
	obj := objects.nginxpod({"image": "nginx", "imagePullPolicy": "Foo"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_replace_deployment = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "Deployment", "imagePullPolicy": "Foo"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_replace_daemonset = x {
	obj := objects.nginx_daemonset({"image": "nginx", "imagePullPolicy": "Foo"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_replace_replicaset = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "ReplicaSet", "imagePullPolicy": "Foo"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_replace_statefulset = x {
	obj := objects.nginx_statefulset({"image": "nginx", "imagePullPolicy": "Foo"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

# set_image_pull_policy_always_if_latest_nop_{pod,deployment,daemonset,replicaset,statefulset} tests a non-latest image, thus nop.
set_image_pull_policy_always_if_latest_nop_pod = x {
	obj := objects.nginxpod({"image": "nginx:mutating.0.0.0"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_nop_deployment = x {
	obj := objects.nginx_uber({"image": "nginx:mutating.0.0.0", "kind": "Deployment"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_nop_daemonset = x {
	obj := objects.nginx_daemonset({"image": "nginx:mutating.0.0.0"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_nop_replicaset = x {
	obj := objects.nginx_uber({"image": "nginx:mutating.0.0.0", "kind": "ReplicaSet"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

set_image_pull_policy_always_if_latest_nop_statefulset = x {
	obj := objects.nginx_statefulset({"image": "nginx:mutating.0.0.0"})
	x := mutating.set_image_pull_policy_always_if_latest with input as objects.admission(obj)
}

# ------------------------------------------------------------------------------
# Inherit namespace labels

test_inherit_namespace_labels_add {
	count(inherit_namespace_labels_add) == 1
	inherit_namespace_labels_add[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'foo' to 'bar' (inherited from namespace 'default')",
		"patch": [{
			"op": "add",
			"path": "/metadata/labels/foo",
			"value": "bar",
		}],
	}
}

test_inherit_namespace_labels_override {
	count(inherit_namespace_labels_override) == 1
	inherit_namespace_labels_override[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'foo' to 'bar' (inherited from namespace 'default', overriding existing value 'baz')",
		"patch": [{
			"op": "replace",
			"path": "/metadata/labels/foo",
			"value": "bar",
		}],
	}
}

test_inherit_namespace_labels_nop_add {
	count(inherit_namespace_labels_nop_add) == 0
}

test_inherit_namespace_labels_nop_override {
	count(inherit_namespace_labels_nop_override) == 0
}

test_inherit_namespace_labels_add_slash_escape {
	count(inherit_namespace_labels_add_slash_escape) == 1
	inherit_namespace_labels_add_slash_escape[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'foo/baz' to 'bar' (inherited from namespace 'default')",
		"patch": [{
			"op": "add",
			"path": "/metadata/labels/foo~1baz",
			"value": "bar",
		}],
	}
}

test_inherit_namespace_labels_override_escape_slash {
	count(inherit_namespace_labels_override_escape_slash) == 1
	inherit_namespace_labels_override_escape_slash[decision]
	decision == {
		"allowed": true,
		"message": "Set label 'foo/baz' to 'bar' (inherited from namespace 'default', overriding existing value 'baz')",
		"patch": [{
			"op": "replace",
			"path": "/metadata/labels/foo~1baz",
			"value": "bar",
		}],
	}
}

# inherit_namespace_labels_add properly inherits a label from namespace to a resource which does not already have it.
inherit_namespace_labels_add = x {
	obj := objects.nginxpod({"namespace": "default"})
	ns := {"metadata": {"name": "default", "labels": {"foo": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_add": ["foo"]} with input as objects.admission(obj)
}

# inherit_namespace_labels_override properly overrides a label using value from the namespace.
inherit_namespace_labels_override = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "baz"}})
	ns := {"metadata": {"name": "default", "labels": {"foo": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_override": ["foo"]} with input as objects.admission(obj)
}

# inherit_namespace_labels_nop_add attempts to add an existing label, thus nop.
inherit_namespace_labels_nop_add = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "baz"}})
	ns := {"metadata": {"name": "default", "labels": {"foo": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_add": ["foo"]} with input as objects.admission(obj)
}

# inherit_namespace_labels_nop attempts to override a non-existing label, thus nop.
inherit_namespace_labels_nop_override = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo": "baz"}})
	ns := {"metadata": {"name": "default", "labels": {"foo": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_override": ["bar"]} with input as objects.admission(obj)
}

# inherit_namespace_labels_add_slash_escape properly inherits a leabel from namespace to a resource which does not already have it and properly escapes slashes.
inherit_namespace_labels_add_slash_escape = x {
	obj := objects.nginxpod({"namespace": "default"})
	ns := {"metadata": {"name": "default", "labels": {"foo/baz": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_add": ["foo/baz"]} with input as objects.admission(obj)
}

# inherit_namespace_labels_override_escape_slash properly overrides a label using value from the namespace and properly escapes slashes.
inherit_namespace_labels_override_escape_slash = x {
	obj := objects.nginxpod({"namespace": "default", "labels": {"foo/baz": "baz"}})
	ns := {"metadata": {"name": "default", "labels": {"foo/baz": "bar"}}}
	x := mutating.inherit_namespace_labels with data.kubernetes.resources.namespaces as {"default": ns} with data.library.parameters as {"labels_to_override": ["foo/baz"]} with input as objects.admission(obj)
}

# ------------------------------------------------------------------------------
# Add default memory resource limits

test_add_default_memory_limit_pod {
	count(add_default_memory_limit_pod) == 1
	add_default_memory_limit_pod[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Pod/default/frontend on container nginx's memory limit to 64Mi",
		"patch": [{
			"op": "add",
			"path": "/spec/containers/0/resources/limits/memory",
			"value": "64Mi",
		}],
	}
}

test_add_default_memory_limit_deployment {
	count(add_default_memory_limit_deployment) == 1
	add_default_memory_limit_deployment[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Deployment/default/frontend on container nginx's memory limit to 64Mi",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/memory",
			"value": "64Mi",
		}],
	}
}

test_add_default_memory_limit_daemonset {
	count(add_default_memory_limit_daemonset) == 1
	add_default_memory_limit_daemonset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource DaemonSet/default/frontend on container nginx's memory limit to 64Mi",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/memory",
			"value": "64Mi",
		}],
	}
}

test_add_default_memory_limit_replicaset {
	count(add_default_memory_limit_replicaset) == 1
	add_default_memory_limit_replicaset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource ReplicaSet/default/frontend on container nginx's memory limit to 64Mi",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/memory",
			"value": "64Mi",
		}],
	}
}

test_add_default_memory_limit_statefulset {
	count(add_default_memory_limit_statefulset) == 1
	add_default_memory_limit_statefulset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource StatefulSet/default/frontend on container nginx's memory limit to 64Mi",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/memory",
			"value": "64Mi",
		}],
	}
}

test_add_default_memory_limit_nop_pod {
	count(add_default_memory_limit_nop_pod) == 0
}

test_add_default_memory_limit_nop_deployment {
	count(add_default_memory_limit_nop_deployment) == 0
}

test_add_default_memory_limit_nop_daemonset {
	count(add_default_memory_limit_nop_daemonset) == 0
}

test_add_default_memory_limit_nop_replicaset {
	count(add_default_memory_limit_nop_replicaset) == 0
}

test_add_default_memory_limit_nop_statefulset {
	count(add_default_memory_limit_nop_statefulset) == 0
}

# add_default_memory_limit_{pod,deployment,daemonset,replicaset,statefulset} sets the resource limit to the default value if not set.
add_default_memory_limit_pod = x {
	obj := objects.nginxpod({"image": "nginx:latest"})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_deployment = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "Deployment"})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_daemonset = x {
	obj := objects.nginx_daemonset({"image": "nginx"})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_replicaset = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "ReplicaSet"})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_statefulset = x {
	obj := objects.nginx_statefulset({"image": "nginx"})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

# add_default_memory_limit_nop_{pod,deployment,daemonset,replicaset,statefulset} attempts to add a resource limit which already exists, thus nop.
add_default_memory_limit_nop_pod = x {
	obj := objects.nginxpod({"resourceLimits": {"memory": "128Mi"}})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_nop_deployment = x {
	obj := objects.nginx_uber({"resourceLimits": {"memory": "128Mi"}})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_nop_daemonset = x {
	obj := objects.nginx_daemonset({"resourceLimits": {"memory": "128Mi"}})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_nop_replicaset = x {
	obj := objects.nginx_uber({"resourceLimits": {"memory": "128Mi"}})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

add_default_memory_limit_nop_statefulset = x {
	obj := objects.nginx_statefulset({"resourceLimits": {"memory": "128Mi"}})
	x := mutating.add_default_memory_limit with data.library.parameters as {"memory_limit": "64Mi"}
		with input as objects.admission(obj)
}

# ------------------------------------------------------------------------------
# Add default cpu resource limits

test_add_default_cpu_limit_pod {
	count(add_default_cpu_limit_pod) == 1
	add_default_cpu_limit_pod[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Pod/default/frontend on container nginx's cpu limit to 250m",
		"patch": [{
			"op": "add",
			"path": "/spec/containers/0/resources/limits/cpu",
			"value": "250m",
		}],
	}
}

test_add_default_cpu_limit_deployment {
	count(add_default_cpu_limit_deployment) == 1
	add_default_cpu_limit_deployment[decision]
	decision == {
		"allowed": true,
		"message": "Set resource Deployment/default/frontend on container nginx's cpu limit to 250m",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/cpu",
			"value": "250m",
		}],
	}
}

test_add_default_cpu_limit_daemonset {
	count(add_default_cpu_limit_daemonset) == 1
	add_default_cpu_limit_daemonset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource DaemonSet/default/frontend on container nginx's cpu limit to 250m",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/cpu",
			"value": "250m",
		}],
	}
}

test_add_default_cpu_limit_replicaset {
	count(add_default_cpu_limit_replicaset) == 1
	add_default_cpu_limit_replicaset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource ReplicaSet/default/frontend on container nginx's cpu limit to 250m",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/cpu",
			"value": "250m",
		}],
	}
}

test_add_default_cpu_limit_statefulset {
	count(add_default_cpu_limit_statefulset) == 1
	add_default_cpu_limit_statefulset[decision]
	decision == {
		"allowed": true,
		"message": "Set resource StatefulSet/default/frontend on container nginx's cpu limit to 250m",
		"patch": [{
			"op": "add",
			"path": "/spec/template/spec/containers/0/resources/limits/cpu",
			"value": "250m",
		}],
	}
}

test_add_default_cpu_limit_nop_pod {
	count(add_default_cpu_limit_nop_pod) == 0
}

test_add_default_cpu_limit_nop_deployment {
	count(add_default_cpu_limit_nop_deployment) == 0
}

test_add_default_cpu_limit_nop_daemonset {
	count(add_default_cpu_limit_nop_daemonset) == 0
}

test_add_default_cpu_limit_nop_replicaset {
	count(add_default_cpu_limit_nop_replicaset) == 0
}

test_add_default_cpu_limit_nop_statefulset {
	count(add_default_cpu_limit_nop_statefulset) == 0
}

# add_default_cpu_limit_{pod,deployment,daemonset,replicaset,statefulset} sets the resource limit to the default value if not set.
add_default_cpu_limit_pod = x {
	obj := objects.nginxpod({"image": "nginx:latest"})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_deployment = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "Deployment"})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_daemonset = x {
	obj := objects.nginx_daemonset({"image": "nginx"})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_replicaset = x {
	obj := objects.nginx_uber({"image": "nginx", "kind": "ReplicaSet"})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_statefulset = x {
	obj := objects.nginx_statefulset({"image": "nginx"})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

# add_default_cpu_limit_nop_{pod,deployment,daemonset,replicaset,statefulset} attempts to add a resource limit which already exists, thus nop.
add_default_cpu_limit_nop_pod = x {
	obj := objects.nginxpod({"resourceLimits": {"cpu": "500m"}})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_nop_deployment = x {
	obj := objects.nginx_uber({"resourceLimits": {"cpu": "500m"}})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_nop_daemonset = x {
	obj := objects.nginx_daemonset({"resourceLimits": {"cpu": "500m"}})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_nop_replicaset = x {
	obj := objects.nginx_uber({"resourceLimits": {"cpu": "500m"}})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

add_default_cpu_limit_nop_statefulset = x {
	obj := objects.nginx_statefulset({"resourceLimits": {"cpu": "500m"}})
	x := mutating.add_default_cpu_limit with data.library.parameters as {"cpu_limit": "250m"}
		with input as objects.admission(obj)
}

test_istio_opa_patches {
	parameters := {
		"channel": "Regular",
		"config": "opa-istio-config",
		"label": "istio-injection",
		"label-value": "enabled",
	}

	test := {"op": "add"}

	mutating.istio_opa_patches[patch] with data.library.parameters as parameters
		with opa_utils.injectable_object as true
		with opa_utils.opa_patch as test
		with opa_utils.opa_volume_patch as test

	p := patch[_]
	p.op == "add"
}

test_envoy_and_opa_patches {
	parameters := {
		"channel": "Regular",
		"config": "opa-envoy-config",
		"config-envoy": "envoy-config",
		"label": "inject-opa",
		"use-socket": "Yes",
		"label-value": "enabled",
	}

	test := {"op": "add"}

	mutating.envoy_and_opa_patches[patch] with data.library.parameters as parameters
		with opa_utils.injectable_object as true
		with opa_utils.opa_patch as test
		with opa_utils.opa_volume_patch as test
		with envoy_utils.init_patch as test
		with envoy_utils.envoy_patch as test
		with envoy_utils.opa_and_envoy_volume_patch as []

	p := patch[_]
	p.op == "add"
}
