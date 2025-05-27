package library.v1.kubernetes.utils.test_v1

import data.library.v1.kubernetes.utils.v1

# wrapped := {"request": {"object": resource, "namespace": namespace, "operation": "CREATE", "kind": {"kind": resource_name_to_kind[kind]}}}
test_admission_namespaced {
	params := {
		"pluralkind": "pods",
		"namespace": "bar",
		"name": "foo",
		"operation": "CREATE",
		"username": "alice",
	}

	actual := v1.admission_with_namespace(nginx_pod, params)
	actual.request.kind.kind == "Pod"

	# actual.request.kind.group == ""
	# actual.request.kind.version == "v1"
	# actual.resource ...
	actual.request.operation == "CREATE"
	actual.request.userInfo.username == "alice"
	actual.request.object.spec.containers[0].name == "frontend"

	actual.request.namespace == "bar"
}

test_admission_namespaced_no_pluralkind {
	# Either pluralkind or kind must be specified, so this test ensures
	# admission_with_namespace is functional without a pluralkind param
	params := {
		"kind": "Pod",
		"namespace": "bar",
		"name": "foo",
		"operation": "CREATE",
		"username": "alice",
	}

	actual := v1.admission_with_namespace(nginx_pod, params)
	actual.request.kind.kind == "Pod"
	actual.request.operation == "CREATE"
	actual.request.userInfo.username == "alice"
	actual.request.object.spec.containers[0].name == "frontend"
	actual.request.namespace == "bar"
}

test_admission_nonnamespaced {
	params := {
		"pluralkind": "pods",
		"name": "foo",
		"operation": "CREATE",
		"username": "alice",
	}

	actual := v1.admission_no_namespace(nginx_pod, params)
	actual.request.kind.kind == "Pod"

	# actual.request.kind.group == ""
	# actual.request.kind.version == "v1"
	# actual.resource ...
	actual.request.operation == "CREATE"
	actual.request.userInfo.username == "alice"
	actual.request.object.spec.containers[0].name == "frontend"
}

test_admission_nonnamespaced_no_pluralkind {
	# Either pluralkind or kind must be specified, so this test ensures
	# admission_no_namespace is functional without a pluralkind param
	params := {
		"kind": "Pod",
		"name": "foo",
		"operation": "CREATE",
		"username": "alice",
	}

	actual := v1.admission_no_namespace(nginx_pod, params)
	actual.request.kind.kind == "Pod"
	actual.request.operation == "CREATE"
	actual.request.userInfo.username == "alice"
	actual.request.object.spec.containers[0].name == "frontend"
}

nginx_pod = {
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {
		"name": "foo",
		"namespace": "bar",
	},
	"spec": {"containers": [{
		"name": "frontend",
		"image": "nginx",
	}]},
}

# ------------------------------------------------------------------------------
# Filters

input_includes_requirements_input = {"request": {
	"kind": {"kind": "Service"},
	"object": {"metadata": {
		"labels": {
			"compliance.cicd.co/pci": "",
			"environment": "production",
			"owner": "devops-eu/finance",
			"phase": "release",
			"hooli.com/private.prod": "foo",
		},
		"annotations": {
			"imageregistry": "https://hub.docker.com/",
			"buildtool": "tool1",
		},
		"namespace": "internal",
	}},
}}

use_input_includes_requirements = x {
	x := v1.input_includes_requirements(data.requirements)
}

test_input_includes_requirements_hit_empty {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {}
}

test_input_includes_requirements_hit_all {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {
			"kinds": {
				"Deployment",
				"Service",
				"StatefulSet",
			},
			"labels": {
				"owner": {"devops-*/finance"},
				"phase": {
					"ga",
					"release",
				},
			},
			"annotations": {"imageregistry": {"https://hub.docker.com/"}},
			"namespaces": {
				"internal",
				"private",
			},
		}
}

test_input_includes_requirements_miss_all {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {
			"kinds": {
				"DaemonSet",
				"Pod",
			},
			"labels": {
				"owner": {"devops-*/finance"},
				"phase": {
					"dev",
					"test",
				},
			},
			"annotations": {"imageregistry": {"https://github.com/"}},
			"namespaces": {"internal"},
		}
}

test_input_includes_kinds_hit {
	requirements := {"kinds": {
		"Deployment",
		"Service",
		"StatefulSet",
	}}

	v1.input_includes_kinds(requirements) with input as input_includes_requirements_input
}

test_input_includes_requirements_hit_kinds {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"kinds": {
			"Deployment",
			"Service",
			"StatefulSet",
		}}
}

test_input_includes_requirements_miss_kinds {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"kinds": {
			"DaemonSet",
			"Pod",
		}}
}

test_input_includes_requirements_glob_hit_kinds {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"kinds": {"*"}}
}

test_input_includes_requirements_glob_miss_kinds {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"kinds": {"D*"}} # since sample input kind is "Service"
}

test_input_includes_labels_hit {
	requirements := {"labels": {
		"owner": {"devops-*/finance"},
		"phase": {
			"ga",
			"release",
		},
	}}

	v1.input_includes_labels(requirements) with input as input_includes_requirements_input
}

test_input_includes_requirements_hit_labels {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {
			"owner": {"devops-*/finance"},
			"phase": {
				"ga",
				"release",
			},
		}}
}

test_input_includes_requirements_miss_labels {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {
			"owner": {"devops-us/*"},
			"phase": {
				"dev",
				"test*",
			},
		}}
}

test_input_includes_requirements_hit_keys_delimiter {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {"hooli.com/*.prod": {"foo"}}}
}

test_input_includes_requirements_miss_keys_delimiter {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {"hooli.*.prod": {"foo"}}}
}

test_input_includes_requirements_hit_labels_with_glob_key {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {
			"own?": {"devops-*/finance"},
			"pha*": {
				"ga",
				"release",
			},
		}}
}

test_input_includes_requirements_miss_labels_with_glob_key {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"labels": {
			# key pri* will not match "owner"
			"pri*": {"devops-us/*"},
			# key sta* will not match "phase"
			"sta*": {
				"dev",
				"test*",
			},
		}}
}

test_input_includes_requirements_hit_annotations {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"annotations": {"buildtool": {"tool*"}}}
}

test_input_includes_annotations_hit {
	requirements := {"annotations": {"buildtool": {"tool*"}}}
	v1.input_includes_annotations(requirements) with input as input_includes_requirements_input
}

test_input_includes_requirements_miss_annotations {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"annotations": {"buildtool": {"tool2"}}}
}

test_input_includes_namespaces_hit {
	requirements := {"namespaces": {"internal"}}
	v1.input_includes_namespaces(requirements) with input as input_includes_requirements_input
}

test_input_includes_requirements_hit_namespaces {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"namespaces": {"internal"}}
}

test_input_includes_requirements_miss_namespaces {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"namespaces": {"private"}}
}

test_input_includes_requirements_glob_hit_namespaces {
	use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"namespaces": {"in*"}}
}

test_input_includes_requirements_glob_miss_namespaces {
	not use_input_includes_requirements with input as input_includes_requirements_input
		with data.requirements as {"namespaces": {"ex*"}} # since sample input namespace is "internal"
}

input_excludes_requirements_input = {"request": {
	"kind": {"kind": "Service"},
	"object": {"metadata": {
		"labels": {
			"compliance.cicd.co/pci": "",
			"environment": "production",
			"owner": "devops-eu/finance",
			"phase": "release",
		},
		"annotations": {
			"imageregistry": "https://hub.docker.com/",
			"buildtool": "tool1",
		},
		"namespace": "internal",
	}},
}}

use_input_excludes_requirements = x {
	x := v1.input_excludes_requirements(data.requirements)
}

test_input_excludes_requirements_hit_empty {
	# totally empty requirements
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {}

	# kind value is empty
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kind": set()}

	# all values are empty
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kind": set(), "labels": set(), "annotations": set(), "namespaces": set()}

	# invalid keys in requirements
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"foo": {"Service"}, "bar": set(), "baz": set()}
}

test_input_excludes_requirements_hit_all {
	# every requirements field has a matching value
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {
			"kinds": {
				"Deployment",
				"Service",
				"StatefulSet",
			},
			"labels": {
				"owner": {"devops-*/finance"},
				"phase": {
					"ga",
					"release",
				},
			},
			"annotations": {"imageregistry": {"https://hub.docker.com/"}},
			"namespaces": {
				"internal",
				"private",
			},
		}

	# no requirements field has a matching value
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {
			"kinds": {
				"Deployment",
				"StatefulSet",
			},
			"labels": {
				"owner": {"devops-*/nomatch"},
				"phase": {
					"beta",
					"ga",
				},
			},
			"annotations": {"imageregistry": {"no-match"}},
			"namespaces": {"private"},
		}
}

test_input_excludes_requirements_hit_kinds {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kinds": {
			"Deployment",
			"Service",
			"StatefulSet",
		}}
}

test_input_excludes_requirements_miss_kinds {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kinds": {
			"DaemonSet",
			"Pod",
		}}
}

test_input_excludes_requirements_glob_hit_kinds {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kinds": {"S*"}}
}

test_input_excludes_requirements_glob_miss_kinds {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"kinds": {"D*"}} # since input is `Service`
}

test_input_excludes_requirements_hit_namespaces {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"namespaces": {
			"internal",
			"another-namespace",
		}}
}

test_input_excludes_requirements_miss_namespaces {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"namespaces": {"private"}}
}

test_input_excludes_requirements_undefined_namespaces {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"namespaces": {}}

	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {}
}

test_input_excludes_requirements_glob_hit_namespaces {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"namespaces": {
			"int*",
			"another-namespace",
		}}
}

test_input_excludes_requirements_glob_miss_namespaces {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"namespaces": {
			"pri*",
			"another-namespace",
		}}
}

test_input_excludes_requirements_hit_labels {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {
			"owner": {"devops-*/finance"},
			"phase": {
				"ga",
				"release",
			},
		}}
}

test_input_excludes_requirements_miss_labels {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {
			"owner": {"devops-us/*"},
			"phase": {
				"dev",
				"test",
			},
		}}
}

test_input_excludes_requirements_hit_annotations {
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"annotations": {"buildtool": {"tool1"}}}
}

test_input_excludes_requirements_miss_annotations {
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"annotations": {"buildtool": {"tool2"}}}
}

test_input_excludes_requirements_labels {
	# label glob in input (input has "owner": "devops-eu/finance")
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {"owner": {"devops-eu/*"}}}

	# label glob in input with some non-matching values (input has "owner": "devops-eu/finance")
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {"owner": {"no-match", "not-a-match", "devops-eu/*"}}}

	# label glob not in input
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {"owner": {"devops-us/*"}}}
}

test_input_excludes_requirements_labels_multiple_requirements {
	# multiple non-matching labels
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"labels": {
			"owner": {"devops-us/*"}, # input value is devops-eu/finance
			"environment": {"test", "stage"}, # input value is production
			"not-in-input": {"foo"},
		}}
}

test_input_excludes_requirements_multiple {
	# neither field matches
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {
			"labels": {"nomatch": {"value1", "value2", "value3"}},
			"annotations": {"nomatch": {"no-match"}},
		}

	# labels field matches, but not annotations
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {
			"labels": {"owner": {"devops-eu/*"}},
			"annotations": {"nomatch": {"no-match"}},
		}

	# both labels and annotations fields match
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {
			"labels": {"owner": {"no-match", "devops-eu/*"}},
			"annotations": {"buildtool": {"tool1"}},
		}
}

test_input_excludes_requirements_multiple_values {
	# both requirement annotations match
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"annotations": {
			"buildtool": {"tool1"},
			"imageregistry": {"https://hub.docker.com/"},
		}}

	# one requirement annotation matches
	not use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"annotations": {
			"buildtool": {"tool1"},
			"imageregistry": {"no-match"},
		}}

	# neither requirement annotation matches
	use_input_excludes_requirements with input as input_excludes_requirements_input
		with data.requirements as {"annotations": {
			"buildtool": {"no-match"},
			"imageregistry": {"no-match"},
		}}
}

test_input_excludes_requirements_missing_fields {
	# create inputs that contain exactly one of the fields that can be used in the exclude filter
	ns_only := json.filter(input_excludes_requirements_input, ["request/object/metadata/namespace"])
	labels_only := json.filter(input_excludes_requirements_input, ["request/object/metadata/labels"])
	kind_only := json.filter(input_excludes_requirements_input, ["request/kind"])

	# totally empty requirements with each input
	use_input_excludes_requirements with data.requirements as {}
		with input as ns_only

	use_input_excludes_requirements with data.requirements as {}
		with input as labels_only

	use_input_excludes_requirements with data.requirements as {}
		with input as kind_only

	# exclude one field that is present in the input and one that is not
	use_input_excludes_requirements with input as ns_only
		with data.requirements as {
			"labels": {"nomatch": {"value1", "value2", "value3"}}, # matches because input does not have any labels
			"namespace": "internal",
		}

	use_input_excludes_requirements with input as labels_only
		with data.requirements as {
			"labels": {"phase": "release"},
			"namespace": "internal", # matches because input does not have a namespace
		}
}
