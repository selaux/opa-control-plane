package library.v1.kubernetes.admission.network.test_v1

import data.library.v1.kubernetes.admission.network.v1
import data.library.v1.kubernetes.admission.test_objects.v1 as objects
import data.library.v1.kubernetes.admission.util.v1 as util

test_k8s_netpol_egress_entity_src_port_whitelist {
	in := input_network_policy_ports_egress("a6379")
	actual := v1.netpol_egress_entity_src_port_whitelist with input as in

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_whitelist_ok {
	in := input_network_policy_ports_egress("a6397")
	p := {
		"approved_named_ports": {"TCP": {"a6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_whitelist_ok_number {
	in := input_network_policy_ports_egress(1111)
	p := {
		"approved_named_ports": {"TCP": {"a6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_whitelist_ok_no_port {
	in := input_network_policy_ports_egress_no_port
	p := {
		"approved_named_ports": {"TCP": {"6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_whitelist_fail {
	in := input_network_policy_ports_egress("a6379")
	p := {
		"approved_named_ports": {"TCP": {"a3333"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_port_whitelist_fail_number {
	in := input_network_policy_ports_egress(3333)
	p := {
		"approved_named_ports": {"TCP": {"a3333"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_selector_other_api {
	in := input_network_policy_namespace_extention_egress

	p := {"approved_namespace_selectors": {"project": {"notmatch"}, "notmatch": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_no_parameters {
	in := input_network_policy_both_selector_egress

	actual := v1.netpol_egress_label_selector_whitelist with input as in

	count(actual) == 0
}

test_k8s_egress_selector_namespace_match {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_namespace_value_no_match {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"project": {"nomatch"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_selector_namespace_key_no_match {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"nomatch": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_selector_namespace_extra_key_ok {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_namespace_empty_value_ignored {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"project": {}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_namespace_empty_value_ignored_extra {
	in := input_network_policy_namespace_egress
	p := {"approved_namespace_selectors": {"project": {}, "stage": {"prod"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_pod_match {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_pod_value_no_match {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"project": {"notmatch"}, "somethingelse": {"do not care"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_selector_pod_key_no_match {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"nomatch": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_selector_pod_extra_key_ok {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"project": {"myproject"}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_pod_empty_value_ignored {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"project": {}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_selector_pod_empty_value_ignored_extra {
	in := input_network_policy_pod_egress
	p := {"approved_pod_selectors": {"project": {}, "extra": {}, "stage": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_both_selector_match {
	in := input_network_policy_both_selector_egress
	p := {
		"approved_pod_selectors": {"service": {"storage"}},
		"approved_namespace_selectors": {"project": {"myproject"}},
	}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_both_selector_namespace_fail {
	in := input_network_policy_both_selector_egress
	p := {"approved_pod_selectors": {"service": {"storage"}}, "approved_namespace_selectors": {"project": {"error"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_pod_fail {
	in := input_network_policy_both_selector_egress
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "extra": {}}, "approved_pod_selectors": {"service": {"sss"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_and_match {
	in := input_network_policy_both_selector_and_egress
	p := {
		"approved_pod_selectors": {"service": {"storage"}},
		"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}},
	}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_both_selector_and_pod_fail {
	in := input_network_policy_both_selector_and_egress
	p := {"approved_pod_selectors": {"service": {"ste"}}, "approved_namespace_selectors": {"project": {"myproject"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_and_pod_glob_fail {
	in := input_network_policy_both_selector_and_egress
	p := {"approved_pod_selectors": {"service": {"stppo*"}}, "approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_and_pod_glob_key_ok {
	in := input_network_policy_both_selector_and_egress
	p := {"approved_pod_selectors": {"service": {"*sto*"}}, "approved_namespace_selectors": {"project": {"*roject"}, "stage": {"*od"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_both_selector_and_namespace_fail {
	in := input_network_policy_both_selector_and_egress
	p := {"approved_pod_selectors": {"service": {"storage"}}, "approved_namespace_selectors": {"project": {"xx"}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_and_both_fail {
	in := input_network_policy_both_selector_and_egress
	p := {"approved_pod_selectors": {"service": {"wrong"}}, "approved_namespace_selectors": {"project": {"wrong"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_egress_both_selector_glob_pod_ok {
	in := input_network_policy_both_selector_egress
	p := {"approved_pod_selectors": {"service": {"stor*"}}, "approved_namespace_selectors": {"project": {"myproject"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_egress_both_selector_glob_pod_fail {
	in := input_network_policy_both_selector_egress
	p := {"approved_pod_selectors": {"project": {"myproject"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_egress_both_selector_both_fail {
	in := input_network_policy_both_selector_egress
	p := {"approved_pod_selectors": {"service": {"wrong"}}, "approved_namespace_selectors": {"project": {"wrong"}, "extra": {}}}

	actual := v1.netpol_egress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_netpol_egress_entity_src_namespace_not_in_blacklist_no_parameter {
	in := input_network_policy_namespace_egress

	actual := v1.netpol_egress_entity_src_namespace_not_in_blacklist with input as in

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_namespace_not_in_blacklist_ok {
	in := input_network_policy_namespace_egress

	p := {"prohibited_namespace_selectors": {"project": {"notmatch"}, "notmatch": {"prod"}}}

	actual := v1.netpol_egress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_namespace_not_in_blacklist_fail {
	in := input_network_policy_namespace_egress

	p := {"prohibited_namespace_selectors": {"project": {"myproject"}, "notmatch": {"prod"}}}

	actual := v1.netpol_egress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_namespace_not_in_blacklist_glob_fail {
	in := input_network_policy_namespace_egress

	p := {"prohibited_namespace_selectors": {"project": {"my*"}, "notmatch": {"prod"}}}

	actual := v1.netpol_egress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_namespace_not_in_blacklist_empty_fail {
	in := input_network_policy_namespace_egress

	p := {"prohibited_namespace_selectors": {"project": {}, "notmatch": {"prod"}}}

	actual := v1.netpol_egress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_network_policy_ports_egress(port) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{
						"to": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP", "port": port}],
					}],
				},
			},
		},
	}
}

input_network_policy_namespace_egress = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{"to": [{"namespaceSelector": {"matchLabels": {"project": "myproject", "stage": "prod"}}}]}],
				},
			},
		},
	}
}

input_network_policy_namespace_extention_egress = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{"to": [{"namespaceSelector": {"matchLabels": {"project": "notmatch"}}}]}],
				},
			},
		},
	}
}

input_network_policy_pod_egress = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{"to": [{"podSelector": {"matchLabels": {"project": "myproject", "stage": "prod"}}}]}],
				},
			},
		},
	}
}

input_network_policy_both_selector_egress = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{"to": [
						{"podSelector": {"matchLabels": {"service": "storage"}}},
						{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					]}],
				},
			},
		},
	}
}

input_network_policy_both_selector_and_egress = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Egress"],
					"egress": [{"to": [{
						"podSelector": {"matchLabels": {"service": "storage"}},
						"namespaceSelector": {"matchLabels": {"project": "myproject"}},
					}]}],
				},
			},
		},
	}
}

test_k8s_netpol_ingress_entity_src_port_whitelist {
	in := input_network_policy_ports_whitelist("a6379")
	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_whitelist_ok {
	in := input_network_policy_ports_whitelist("a6397")
	p := {
		"approved_named_ports": {"TCP": {"a6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_whitelist_ok_number {
	in := input_network_policy_ports_whitelist(1111)
	p := {
		"approved_named_ports": {"TCP": {"a6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_whitelist_ok_no_port {
	in := input_network_policy_ports_no_port
	p := {
		"approved_named_ports": {"TCP": {"a6397"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_whitelist_fail {
	in := input_network_policy_ports_whitelist("a6379")
	p := {
		"approved_named_ports": {"TCP": {"a3333"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_port_whitelist_fail_number {
	in := input_network_policy_ports_whitelist(3333)
	p := {
		"approved_named_ports": {"TCP": {"a3333"}},
		"approved_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_network_policy_ports_no_port = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{
						"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP"}],
					}],
				},
			},
		},
	}
}

input_network_policy_ports_egress_no_port = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"egress": [{
						"to": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP"}],
					}],
				},
			},
		},
	}
}

input_network_policy_ports_whitelist(port) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{
						"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP", "port": port}],
					}],
				},
			},
		},
	}
}

test_k8s_netpol_ingress_entity_src_port_blacklist {
	in := input_network_policy_ports("a6397")
	actual := v1.netpol_ingress_entity_src_port_blacklist with input as in
	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_blacklist {
	in := input_network_policy_ports_egress("a6397")
	actual := v1.netpol_egress_entity_src_port_blacklist with input as in
	count(actual) == 0
}

test_k8s_ingress_selector_other_api {
	in := input_network_policy_namespace_extention

	p := {"approved_namespace_selectors": {"project": {"notmatch"}, "notmatch": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_namespace_not_in_blacklist_no_parameter {
	in := input_network_policy_namespace

	actual := v1.netpol_ingress_entity_src_namespace_not_in_blacklist with input as in

	count(actual) == 0
}

test_k8s_ingress_selector_no_parameters {
	in := input_network_policy_both_selector

	actual := v1.netpol_ingress_label_selector_whitelist with input as in

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_blacklist_ok {
	in := input_network_policy_ports("a6397")
	p := {
		"prohibited_named_ports": {"TCP": {"79"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_egress_entity_src_port_blacklist_ok {
	in := input_network_policy_ports_egress("a6397")
	p := {
		"prohibited_named_ports": {"TCP": {"a79"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_namespace_not_in_blacklist_ok {
	in := input_network_policy_namespace

	p := {"prohibited_namespace_selectors": {"project": {"notmatch"}, "notmatch": {"prod"}}}

	actual := v1.netpol_ingress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_namespace_match {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_netpol_ingress_entity_src_port_blacklist_fail {
	in := input_network_policy_ports("a6397")
	p := {
		"prohibited_named_ports": {"TCP": {"a6397"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_port_blacklist_fail {
	in := input_network_policy_ports_egress("a6397")
	p := {
		"prohibited_named_ports": {"TCP": {"a6397"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_namespace_not_in_blacklist_fail {
	in := input_network_policy_namespace

	p := {"prohibited_namespace_selectors": {"project": {"myproject"}, "notmatch": {"prod"}}}

	actual := v1.netpol_ingress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_namespace_not_in_blacklist_glob_fail {
	in := input_network_policy_namespace

	p := {"prohibited_namespace_selectors": {"project": {"my*"}, "notmatch": {"prod"}}}

	actual := v1.netpol_ingress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_port_blacklist_fail_number {
	in := input_network_policy_ports(1111)
	p := {
		"prohibited_named_ports": {"TCP": {"6379"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_port_blacklist_fail_number {
	in := input_network_policy_ports_egress(1111)
	p := {
		"prohibited_named_ports": {"TCP": {"6379"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_selector_namespace_value_no_match {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"project": {"nomatch"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_port_blacklist_fail_no_port {
	in := input_network_policy_ports_no_port
	p := {
		"prohibited_named_ports": {"TCP": {"6379"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_ingress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_egress_entity_src_port_blacklist_fail_no_port {
	in := input_network_policy_ports_egress_no_port
	p := {
		"prohibited_named_ports": {"TCP": {"6379"}},
		"prohibited_ports": {"TCP": {1111}},
	}

	actual := v1.netpol_egress_entity_src_port_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_netpol_ingress_entity_src_namespace_not_in_blacklist_empty_fail {
	in := input_network_policy_namespace

	p := {"prohibited_namespace_selectors": {"project": {}, "notmatch": {"prod"}}}

	actual := v1.netpol_ingress_entity_src_namespace_not_in_blacklist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

input_network_policy_ports(port) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{
						"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP", "port": port}],
					}],
				},
			},
		},
	}
}

input_network_policy_ports_no_port = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{
						"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject"}}}],
						"ports": [{"protocol": "TCP"}],
					}],
				},
			},
		},
	}
}

input_network_policy_namespace = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject", "stage": "prod"}}}]}],
				},
			},
		},
	}
}

test_k8s_ingress_selector_namespace_key_no_match {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"nomatch": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_selector_namespace_extra_key_ok {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_namespace_empty_value_ignored {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"project": {}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_namespace_empty_value_ignored_extra {
	in := input_network_policy_namespace
	p := {"approved_namespace_selectors": {"project": {}, "stage": {"prod"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_pod_match {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_pod_value_no_match {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"project": {"notmatch"}, "somethingelse": {"do not care"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_selector_pod_key_no_match {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"nomatch": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_selector_pod_extra_key_ok {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"project": {"myproject"}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_pod_empty_value_ignored {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"project": {}, "stage": {"prod"}, "extra": {"extra"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_selector_pod_empty_value_ignored_extra {
	in := input_network_policy_pod
	p := {"approved_pod_selectors": {"project": {}, "extra": {}, "stage": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_both_selector_match {
	in := input_network_policy_both_selector
	p := {"approved_pod_selectors": {"service": {"storage"}}, "approved_namespace_selectors": {"project": {"myproject"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_both_selector_namespace_fail {
	in := input_network_policy_both_selector
	p := {"approved_pod_selectors": {"service": {"storage"}}, "approved_namespace_selectors": {"project": {"error"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_pod_fail {
	in := input_network_policy_both_selector
	p := {"approved_namespace_selectors": {"project": {"myproject"}, "extra": {}}, "approved_pod_selectors": {"service": {"sss"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_and_match {
	in := input_network_policy_both_selector_and
	p := {
		"approved_pod_selectors": {"service": {"storage"}},
		"approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}},
	}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_both_selector_and_pod_fail {
	in := input_network_policy_both_selector_and
	p := {"approved_pod_selectors": {"service": {"ste"}}, "approved_namespace_selectors": {"project": {"myproject"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_and_pod_glob_fail {
	in := input_network_policy_both_selector_and
	p := {"approved_pod_selectors": {"service": {"stppo*"}}, "approved_namespace_selectors": {"project": {"myproject"}, "stage": {"prod"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_and_pod_glob_key_ok {
	in := input_network_policy_both_selector_and
	p := {"approved_pod_selectors": {"service": {"*sto*"}}, "approved_namespace_selectors": {"project": {"*roject"}, "stage": {"*od"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_both_selector_and_namespace_fail {
	in := input_network_policy_both_selector_and
	p := {"approved_pod_selectors": {"service": {"storage"}}, "approved_namespace_selectors": {"project": {"xx"}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_and_both_fail {
	in := input_network_policy_both_selector_and
	p := {"approved_pod_selectors": {"service": {"wrong"}}, "approved_namespace_selectors": {"project": {"wrong"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_ingress_both_selector_glob_pod_ok {
	in := input_network_policy_both_selector
	p := {"approved_pod_selectors": {"service": {"stor*"}}, "approved_namespace_selectors": {"project": {"myproject"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_ingress_both_selector_glob_pod_fail {
	in := input_network_policy_both_selector
	p := {"approved_pod_selectors": {"project": {"myproject"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_ingress_both_selector_both_fail {
	in := input_network_policy_both_selector
	p := {"approved_pod_selectors": {"service": {"wrong"}}, "approved_namespace_selectors": {"project": {"wrong"}, "extra": {}}}

	actual := v1.netpol_ingress_label_selector_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 2
}

test_k8s_deny_ingress_hostname_not_in_whitelist_bad {
	in := input_with_ingress({"signin.acmecorp.com"}, set())
	p := {"whitelist": {
		"*.qa.acmecorp.com",
		"*.internal.acmecorp.com",
	}}

	actual := v1.deny_ingress_hostname_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_ingress_hostname_not_in_whitelist_no_asterix_bad {
	in := input_with_ingress({"signin.acmecorp.com"}, set())
	p := {"whitelist": {"acmecorp"}}

	actual := v1.deny_ingress_hostname_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_k8s_deny_ingress_hostname_not_in_whitelist_good {
	in := input_with_ingress({"signin.acmecorp.com"}, set())
	p := {"whitelist": {
		"*.qa.acmecorp.com",
		"*.internal.acmecorp.com",
		"*.acmecorp.com",
	}}

	actual := v1.deny_ingress_hostname_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_deny_ingress_hostname_not_in_whitelist_no_asterix_good {
	in := input_with_ingress({"acmecorp"}, set())
	p := {"whitelist": {"acmecorp"}}

	actual := v1.deny_ingress_hostname_not_in_whitelist with input as in
		with data.library.parameters as p

	count(actual) == 0
}

test_k8s_restrict_external_lbs_bad {
	in := input_with_service("LoadBalancer")
	actual := v1.restrict_external_lbs with input as in

	count(actual) == 1
}

test_k8s_restrict_external_lbs_good {
	in := input_with_service("ClusterIP")
	actual := v1.restrict_external_lbs with input as in

	count(actual) == 0
}

##################################
# Ingress TLS
test_k8s_ingress_missing_tls_good {
	params := {"tls": [{"hosts": ["sslexample.foo.com"], "secretName": "testsecret-tls"}]}

	in := input_with_ingress_object(params)
	actual := v1.ingress_missing_tls with input as in
	count(actual) == 0
}

test_k8s_ingress_missing_tls_missing_host_bad {
	params := {"tls": [{"secretName": "testsecret-tls"}]}

	in := input_with_ingress_object(params)
	actual := v1.ingress_missing_tls with input as in
	count(actual) == 1
}

test_k8s_ingress_missing_tls_missing_secret_bad {
	params := {"tls": [{"hosts": ["sslexample.foo.com"]}]}

	in := input_with_ingress_object(params)
	actual := v1.ingress_missing_tls with input as in
	count(actual) == 1
}

test_k8s_ingress_missing_tls_hostempty_bad {
	params := {"tls": [{"hosts": [], "secretName": "testsecret-tls"}]}

	in := input_with_ingress_object(params)
	actual := v1.ingress_missing_tls with input as in
	count(actual) == 1
}

test_k8s_ingress_missing_tls_bad {
	in := input_with_ingress_object({})
	actual := v1.ingress_missing_tls with input as in
	count(actual) == 1
}

##################################
# Ingress conflicts

test_k8s_skip_ingress_host_conflict {
	rule1 := {
		"host": "foo.bar.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s1",
				"servicePort": 80,
			},
			"path": "/foo",
		}]},
	}

	rule2 := {
		"host": "foo.bar.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/foo",
		}]},
	}

	rule_no_host := {"http": {"paths": [{
		"backend": {
			"serviceName": "s2",
			"servicePort": 80,
		},
		"path": "/foo",
	}]}}

	# self
	ing0 := raw_ingress("ns", "foo1", [rule1])
	in0 := input_with_ingress_rules("ns", "foo1", [rule1])
	res0 := build_resource_hierarchy([ing0])
	actual0 := v1.ingress_host_conflict with input as in0
		with data.kubernetes.resources as {"ingresses": res0}

	count(actual0) == 0

	# no host in input
	ing1 := raw_ingress("ns", "foo1", [rule1])
	in1 := input_with_ingress_rules("ns", "foo3", [rule_no_host])
	res1 := build_resource_hierarchy([ing1])
	actual1 := v1.ingress_host_conflict with input as in1
		with data.kubernetes.resources as {"ingresses": res1}

	count(actual1) == 1

	# no host in data
	ing2 := raw_ingress("ns", "foo1", [rule_no_host])
	in2 := input_with_ingress_rules("ns", "foo3", [rule1])
	res2 := build_resource_hierarchy([ing2])
	actual2 := v1.ingress_host_conflict with input as in2
		with data.kubernetes.resources as {"ingresses": res2}

	count(actual2) == 1

	# conflicting hosts
	ing3 := raw_ingress("ns", "foo1", [rule1])
	in3 := input_with_ingress_rules("ns", "foo3", [rule2])
	res3 := build_resource_hierarchy([ing3])
	actual3 := v1.ingress_host_conflict with input as in3
		with data.kubernetes.resources as {"ingresses": res3}

	count(actual3) == 1

	# multiple data
	ing4 := raw_ingress("ns", "foo1", [rule1, rule_no_host])
	in4 := input_with_ingress_rules("ns", "foo3", [rule2])
	res4 := build_resource_hierarchy([ing4])
	actual4 := v1.ingress_host_conflict with input as in4
		with data.kubernetes.resources as {"ingresses": res4}

	count(actual4) == 2
}

test_k8s_skip_ingress_hostpath_conflict {
	rule1 := {
		"host": "initech.com",
		"http": {"paths": [
			{
				"backend": {
					"serviceName": "s1",
					"servicePort": 80,
				},
				"path": "/foo",
			},
			{
				"backend": {
					"serviceName": "s1",
					"servicePort": 80,
				},
				"path": "/bar",
			},
		]},
	}

	rule2 := {
		"host": "initech.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/bar/qux",
		}]},
	}

	rule3 := {
		"host": "hooli.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/bar/qux",
		}]},
	}

	rule4 := {
		"host": "initech.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/bonzo",
		}]},
	}

	rule5 := {
		"host": "initech.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/",
		}]},
	}

	rule_no_host := {"http": {"paths": [{
		"backend": {
			"serviceName": "s2",
			"servicePort": 80,
		},
		"path": "/foo",
	}]}}

	# self-test
	ing0 := raw_ingress("ns", "foo1", [rule1])
	in0 := input_with_ingress_rules("ns", "foo1", [rule1])
	res0 := build_resource_hierarchy([ing0])
	actual0 := v1.ingress_hostpath_conflict with input as in0
		with data.kubernetes.resources as {"ingresses": res0}

	count(actual0) == 0

	# no host in input
	ing1 := raw_ingress("ns", "foo1", [rule1])
	in1 := input_with_ingress_rules("ns", "foo3", [rule_no_host])
	res1 := build_resource_hierarchy([ing1])
	actual1 := v1.ingress_hostpath_conflict with input as in1
		with data.kubernetes.resources as {"ingresses": res1}

	count(actual1) == 1

	# no host in data
	ing2 := raw_ingress("ns", "foo1", [rule_no_host])
	in2 := input_with_ingress_rules("ns", "foo3", [rule1])
	res2 := build_resource_hierarchy([ing2])
	actual2 := v1.ingress_hostpath_conflict with input as in2
		with data.kubernetes.resources as {"ingresses": res2}

	count(actual2) == 1

	# conflicting hosts
	ing3 := raw_ingress("ns", "foo1", [rule1])
	in3 := input_with_ingress_rules("ns", "foo3", [rule2])
	res3 := build_resource_hierarchy([ing3])
	actual3 := v1.ingress_hostpath_conflict with input as in3
		with data.kubernetes.resources as {"ingresses": res3}

	count(actual3) == 1

	# multiple ingresses
	ing4 := raw_ingress("ns", "foo1", [rule1, rule_no_host])
	in4 := input_with_ingress_rules("ns", "foo3", [rule2])
	res4 := build_resource_hierarchy([ing4])
	actual4 := v1.ingress_hostpath_conflict with input as in4
		with data.kubernetes.resources as {"ingresses": res4}

	count(actual4) == 2

	# non-conflicts: paths
	ing5 := raw_ingress("ns", "foo1", [rule2, rule1])
	in5 := input_with_ingress_rules("ns", "foo3", [rule4])
	res5 := build_resource_hierarchy([ing5])
	actual5 := v1.ingress_hostpath_conflict with input as in5
		with data.kubernetes.resources as {"ingresses": res5}

	count(actual5) == 0

	# non-conflicts: paths
	ing6 := raw_ingress("ns", "foo1", [rule2, rule1])
	in6 := input_with_ingress_rules("ns", "foo3", [rule3])
	res6 := build_resource_hierarchy([ing6])
	actual6 := v1.ingress_hostpath_conflict with input as in6
		with data.kubernetes.resources as {"ingresses": res6}

	count(actual6) == 0

	# non-conflicts: conflicting hosts, different paths (root and subpath)
	ing7 := raw_ingress("ns", "foo1", [rule1])
	in7 := input_with_ingress_rules("ns", "foo3", [rule5])
	res7 := build_resource_hierarchy([ing7])
	actual7 := v1.ingress_hostpath_conflict with input as in7
		with data.kubernetes.resources as {"ingresses": res7}

	count(actual7) == 0
}

test_ingress_host_to_paths {
	rule1 := {
		"host": "hooli.com",
		"http": {"paths": [
			{
				"backend": {
					"serviceName": "s1",
					"servicePort": 80,
				},
				"path": "/foo",
			},
			{
				"backend": {
					"serviceName": "s1",
					"servicePort": 80,
				},
				"path": "/bar",
			},
		]},
	}

	rule2 := {
		"host": "hooli.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/qux",
		}]},
	}

	rule3 := {
		"host": "initech.com",
		"http": {
			"host": "hooli.com",
			"paths": [{
				"backend": {
					"serviceName": "s2",
					"servicePort": 80,
				},
				"path": "/bar",
			}],
		},
	}

	actual := v1.ingress_host_to_paths([rule1, rule2, rule3])
	correct := {
		"hooli.com": {"/bar", "/foo", "/qux"},
		"initech.com": {"/bar"},
	}

	actual == correct
}

test_paths_conflict_prefix {
	true == v1.paths_conflict_prefix({"/foo"}, {"/foo/bar"})
	true == v1.paths_conflict_prefix({"foo"}, {"/foo/bar"})
	true == v1.paths_conflict_prefix({"/foo", "qux"}, {"/baz", "/foo/bar"})
	not v1.paths_conflict_prefix({"/foo", "qux"}, {"/baz", "/fod/bar"})
}

test_build_resource_hierarchy {
	res1 := raw_ingress("ns", "foo1", [])
	res2 := raw_ingress("ns", "foo2", [])
	res3 := raw_ingress("ns2", "foo1", [])
	res4 := raw_ingress("ns2", "foo3", [])
	res5 := raw_ingress("ns3", "bar", [])
	actual := build_resource_hierarchy([res1, res2, res3, res4, res5])
	actual.ns.foo1 == res1
	actual.ns.foo2 == res2
	actual.ns2.foo1 == res3
	actual.ns2.foo3 == res4
	actual.ns3.bar == res5
}

input_network_policy_namespace = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"project": "myproject", "stage": "prod"}}}]}],
				},
			},
		},
	}
}

input_network_policy_namespace_extention = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"project": "notmatch"}}}]}],
				},
			},
		},
	}
}

input_network_policy_pod = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [{"podSelector": {"matchLabels": {"project": "myproject", "stage": "prod"}}}]}],
				},
			},
		},
	}
}

input_network_policy_both_selector = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [
						{"podSelector": {"matchLabels": {"service": "storage"}}},
						{"namespaceSelector": {"matchLabels": {"project": "myproject"}}},
					]}],
				},
			},
		},
	}
}

input_network_policy_both_selector_and = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy", "group": "networking.k8s.io", "version": "v1"},
			"namespace": "prod",
			"object": {
				"metadata": {
					"name": "test-network",
					"namespace": "prod",
				},
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"policyTypes": ["Ingress"],
					"ingress": [{"from": [{
						"podSelector": {"matchLabels": {"service": "storage"}},
						"namespaceSelector": {"matchLabels": {"project": "myproject"}},
					}]}],
				},
			},
		},
	}
}

build_resource_hierarchy(resources) = result {
	result := {resource.metadata.namespace: namedict |
		resource := resources[_]
		namedict := {namedresource.metadata.name: namedresource |
			namedresource := resources[_]
			namedresource.metadata.namespace == resource.metadata.namespace
		}
	}
}

raw_ingress(namespace, name, rules) = result {
	result := {
		"apiVersion": "apps/v1",
		"kind": "Ingress",
		"metadata": {
			"name": name,
			"namespace": namespace,
		},
		"spec": {"rules": rules},
	}
}

input_with_network(ing) = x {
	ingress := ing

	egress := [{"to": [
		{"ipBlock": {
			"cidr": "10.0.0.0/24",
			"except": ["10.0.1.0/24"],
		}},
		{"ipBlock": {
			"cidr": "20.0.0.0/24",
			"except": ["20.0.1.0/24"],
		}},
	]}]

	x := {
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"kind": "NetworkPolicy",
				"version": "v1",
				"group": "networking.k8s.io",
			},
			"object": {
				"spec": {
					"policyTypes": [
						"Ingress",
						"Egress",
					],
					"ingress": ingress,
					"egress": egress,
				},
				"metadata": {
					"namespace": "foo",
					"name": "test-network-policy",
				},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_with_service(type) = x {
	x := {
		"request": {
			"kind": {"kind": "Service"},
			"object": {
				"spec": {
					"selector": {"app": "MyApp"},
					"type": type,
					"ports": [{"protocol": "TCP", "port": 80}],
				},
				"metadata": {"name": "my-service"},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

input_with_ingress(hosts, services) = x {
	rules1 := [{"host": host} | hosts[host]]
	rules2 := [{"http": {"paths": [{"backend": {"serviceName": service}}]}} | services[service]]

	rules := array.concat(rules1, rules2)

	x := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": {"name": "foo"},
				"spec": {"rules": rules},
			},
		},
	}
}

input_with_ingress_rules(namespace, name, rules) = x {
	x := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": namespace,
			"operation": "CREATE",
			"object": {
				"metadata": {
					"namespace": namespace,
					"name": name,
				},
				"spec": {"rules": rules},
			},
		},
	}
}

input_with_ingress_object(params) = result {
	default_rules := [{
		"host": "initech.com",
		"http": {"paths": [{
			"backend": {
				"serviceName": "s2",
				"servicePort": 80,
			},
			"path": "/bonzo",
		}]},
	}]

	name := get(params, "name", "foo")
	namespace := get(params, "namespace", "prod")
	rules := get(params, "rules", [])
	spec_req := {"rules": get(params, "rules", default_rules)}
	spec_opt := {x: y |
		keys := {"tls"}
		keys[x]
		params[x]
		y := params[x]
	}

	req_keys := {x | spec_req[x]}
	opt_keys := {x | spec_opt[x]}
	all_keys := req_keys | opt_keys
	spec := {x: y |
		all_keys[x]
		y := get(spec_req, x, get(spec_opt, x, null))
	}

	result := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": namespace,
			"operation": "CREATE",
			"object": {
				"metadata": {
					"namespace": namespace,
					"name": name,
				},
				"spec": spec,
			},
		},
	}
}

##################################
# tests for (allowed | blocked)_cidrs_(from | to)

network_policy_ar(ingress, egress) = x {
	types := {"Ingress" | ingress[_]} | {"Egress" | egress[_]}
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"kind": {"kind": "NetworkPolicy"},
			"namespace": "prod",
			"object": {
				"spec": {
					"podSelector": {"matchLabels": {"role": "db"}},
					"ingress": ingress,
					"egress": egress,
					"policyTypes": types,
				},
				"metadata": {
					"name": "test",
					"namespace": "prod",
				},
			},
		},
	}
}

test_k8s_deny_ingress_ip_block_not_in_whitelist_on_allow_all {
	inp := network_policy_ar([{}], [])
	p := {"whitelist": set()}
	errors := v1.deny_ingress_ip_block_not_in_whitelist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_ingress_ip_block_not_in_whitelist_positive {
	inp := network_policy_ar(
		[
			{"from": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
			{"from": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
		],
		[],
	)

	p1 := {"whitelist": {"172.17.0.0/12"}}
	errors1 := v1.deny_ingress_ip_block_not_in_whitelist with data.library.parameters as p1
		with input as inp

	count(errors1) == 0

	p2 := {"whitelist": {"172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16", "172.20.0.0/16", "172.21.0.0/16"}}
	errors2 := v1.deny_ingress_ip_block_not_in_whitelist with data.library.parameters as p2
		with input as inp

	count(errors2) == 0
}

test_k8s_deny_ingress_ip_block_not_in_whitelist_negative {
	inp := network_policy_ar(
		[
			{"from": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
			{"from": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
		],
		[],
	)

	p := {"whitelist": {"172.17.0.0/16", "172.19.0.0/16", "172.21.0.0/16"}}
	errors := v1.deny_ingress_ip_block_not_in_whitelist with data.library.parameters as p
		with input as inp

	count(errors) = 1
}

test_k8s_deny_ingress_ip_block_in_blacklist_on_allow_all_empty_blacklist {
	inp := network_policy_ar([{}], [])
	p := {"blacklist": set()}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_ingress_ip_block_in_blacklist_on_allow_all {
	inp := network_policy_ar([{}], [])
	p := {"blacklist": {"10.20.30.40/8"}}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_ingress_ip_block_in_blacklist_positive {
	inp := network_policy_ar(
		[
			{"from": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
			{"from": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
		],
		[],
	)

	p := {"blacklist": {"172.21.0.0/16", "172.22.0.0/16"}}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_ingress_ip_block_in_blacklist_except_positive {
	inp := network_policy_ar(
		[{"from": [{"ipBlock": {
			"cidr": "172.17.0.0/16",
			"except": ["172.17.0.0/20"],
		}}]}],
		[],
	)

	p := {"blacklist": {"172.17.0.0/24"}}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_ingress_ip_block_in_blacklist_negative {
	inp := network_policy_ar(
		[
			{"from": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
			{"from": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
		],
		[],
	)

	p := {"blacklist": {"172.18.0.0/24"}}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_ingress_ip_block_in_blacklist_except_negative {
	inp := network_policy_ar(
		[{"from": [{"ipBlock": {
			"cidr": "172.17.0.0/16",
			"except": ["172.17.0.0/20"],
		}}]}],
		[],
	)

	p := {"blacklist": {"172.17.0.0/18"}}
	errors := v1.deny_ingress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_egress_ip_block_not_in_whitelist_on_allow_all {
	inp := network_policy_ar([], [{}])
	p := {"whitelist": set()}
	errors := v1.deny_egress_ip_block_not_in_whitelist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_egress_ip_block_not_in_whitelist_positive {
	inp := network_policy_ar([], [
		{"to": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
		{"to": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
	])

	p1 := {"whitelist": {"172.17.0.0/12"}}
	errors1 := v1.deny_egress_ip_block_not_in_whitelist with data.library.parameters as p1
		with input as inp

	count(errors1) == 0

	p2 := {"whitelist": {"172.17.0.0/16", "172.18.0.0/16", "172.19.0.0/16", "172.20.0.0/16", "172.21.0.0/16"}}
	errors2 := v1.deny_egress_ip_block_not_in_whitelist with data.library.parameters as p2
		with input as inp

	count(errors2) == 0
}

test_k8s_deny_egress_ip_block_not_in_whitelist_negative {
	inp := network_policy_ar([], [
		{"to": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
		{"to": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
	])

	p := {"whitelist": {"172.17.0.0/16", "172.19.0.0/16", "172.21.0.0/16"}}
	errors := v1.deny_egress_ip_block_not_in_whitelist with data.library.parameters as p
		with input as inp

	count(errors) = 1
}

test_k8s_deny_egress_ip_block_in_blacklist_on_allow_all_empty_blacklist {
	inp := network_policy_ar([], [{}])
	p := {"blacklist": set()}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_egress_ip_block_in_blacklist_on_allow_all {
	inp := network_policy_ar([], [{}])
	p := {"blacklist": {"10.20.30.40/8"}}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_egress_ip_block_in_blacklist_positive {
	inp := network_policy_ar([], [
		{"to": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
		{"to": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
	])

	p := {"blacklist": {"172.21.0.0/16", "172.22.0.0/16"}}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_egress_ip_block_in_blacklist_except_positive {
	inp := network_policy_ar([], [{"to": [{"ipBlock": {
		"cidr": "172.17.0.0/16",
		"except": ["172.17.0.0/20"],
	}}]}])

	p := {"blacklist": {"172.17.0.0/24"}}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 0
}

test_k8s_deny_egress_ip_block_in_blacklist_negative {
	inp := network_policy_ar([], [
		{"to": [{"ipBlock": {"cidr": "172.17.0.0/16"}}, {"ipBlock": {"cidr": "172.18.0.0/16"}}]},
		{"to": [{"ipBlock": {"cidr": "172.19.0.0/16"}}, {"ipBlock": {"cidr": "172.20.0.0/16"}}]},
	])

	p := {"blacklist": {"172.18.0.0/24"}}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

test_k8s_deny_egress_ip_block_in_blacklist_except_negative {
	inp := network_policy_ar([], [{"to": [{"ipBlock": {
		"cidr": "172.17.0.0/16",
		"except": ["172.17.0.0/20"],
	}}]}])

	p := {"blacklist": {"172.17.0.0/18"}}
	errors := v1.deny_egress_ip_block_in_blacklist with data.library.parameters as p
		with input as inp

	count(errors) == 1
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_allow_service_ips_is_from_whitelist {
	parameters := {"whitelist": ["2.2.2.2/24", "3.3.3.3/24", "1.1.1.1/24"]}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "1.1.1.1"}},
	}}

	set() == v1.deny_cluster_ip_not_in_whitelist with input as services_yaml
		with data.library.parameters as parameters
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_allow_service_ips_not_from_whitelist {
	parameters := {"whitelist": ["2.2.2.2/24", "3.3.3.3/24", "1.1.1.1/24"]}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "15.1.1.1"}},
	}}

	actual := v1.deny_cluster_ip_not_in_whitelist with input as services_yaml
		with data.library.parameters as parameters

	contains(actual[_], "IP 15.1.1.1 is not included in the allowed list")
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_allow_service_ips_empty_whitelist {
	parameters := {"whitelist": []}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "15.1.1.1"}},
	}}

	actual := v1.deny_cluster_ip_not_in_whitelist with input as services_yaml
		with data.library.parameters as parameters

	contains(actual[_], "with IP 15.1.1.1 is not included in the allowed list")
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_deny_cluster_ip_in_blacklist_service_ip_is_in_blacklist {
	parameters := {"blacklist": ["1.1.1.1/24", "2.2.2.2/24"]}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "1.1.1.1"}},
	}}

	actual := v1.deny_cluster_ip_in_blacklist with input as services_yaml
		with data.library.parameters as parameters

	contains(actual[_], "with IP 1.1.1.1 is a blacklisted IP address")
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_deny_cluster_ip_in_blacklist_service_ip_not_in_blacklist {
	parameters := {"whitelist": ["1.1.1.1/24", "2.2.2.2/24"]}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "16.1.1.1"}},
	}}

	set() == v1.deny_cluster_ip_in_blacklist with input as services_yaml
		with data.library.parameters as parameters
}

# TODO: fix; weird error about allowed address range is in 10.96.0.0/24
test_deny_cluster_ip_in_blacklist_empty_blacklist {
	parameters := {"whitelist": []}
	services_yaml := {"request": {
		"kind": {"kind": "Service"},
		"object": {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "test-service"}, "spec": {"ports": [{"protocol": "TCP", "port": 80}], "clusterIP": "1.1.1.1"}},
	}}

	set() == v1.deny_cluster_ip_in_blacklist with input as services_yaml
		with data.library.parameters as parameters
}

get(args, key, default_value) = x {
	x := args[key]
}

get(args, key, default_value) = default_value {
	not args[key]
}

test_matchesLabels {
	# single valued matcher
	not v1.matchesLabels({}, {"foo": "bar"})
	not v1.matchesLabels({"foo": 17}, {"foo": "bar"})
	not v1.matchesLabels({"foo": "incorrect"}, {"foo": "bar"})

	# good matches
	v1.matchesLabels({"foo": "bar"}, {"foo": "bar"})
	v1.matchesLabels({"foo": "bar", "baz": "qux"}, {"baz": "qux", "foo": "bar"})

	# multi-valued matcher and labels
	not v1.matchesLabels({"baz": "qux"}, {"foo": "bar", "baz": "qux"})
	not v1.matchesLabels({"foo": 17, "baz": "qux"}, {"foo": "bar", "baz": "qux"})
	not v1.matchesLabels({"foo": "incorrect", "baz": "qux"}, {"foo": "bar", "baz": "qux"})
}

# matchExpressions is a list of LabelSelectorsRequirements:
#  A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
#   key is the label key that the selector applies to.
#   operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
#   values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.

test_matchesExpressions {
	# good matches
	v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "in", "values": ["baz", "bar"]}])
	v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "notin", "values": ["baz", "qux"]}])
	v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "exists", "values": []}])
	v1.matchesExpressions({"foo": "bar"}, [{"key": "baz", "operator": "doesnotexist", "values": []}])

	# failed matches
	not v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "in", "values": ["baz"]}])
	not v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "notin", "values": ["baz", "bar"]}])
	not v1.matchesExpressions({"foo": "bar"}, [{"key": "bar", "operator": "exists", "values": []}])
	not v1.matchesExpressions({"foo": "bar"}, [{"key": "foo", "operator": "doesnotexist", "values": []}])

	# multiple expressions
	v1.matchesExpressions({"foo": "bar", "baz": "qux"}, [
		{"key": "baz", "operator": "in", "values": ["qux"]},
		{"key": "foo", "operator": "in", "values": ["bar"]},
	])

	not v1.matchesExpressions({"foo": "bar", "baz": "qux"}, [
		{"key": "baz", "operator": "in", "values": ["qux"]},
		{"key": "foo", "operator": "in", "values": ["qux"]},
	])

	not v1.matchesExpressions({"foo": "bar", "baz": "qux"}, [{"key": "missing", "operator": "in", "values": ["baz", "bar"]}])

	not v1.matchesExpressions({"foo": "bar", "baz": "qux"}, [
		{"key": "baz", "operator": "in", "values": ["qux"]},
		{"key": "foo", "operator": "in", "values": ["baz", "bar"]},
		{"key": "missing", "operator": "in", "values": ["baz", "bar"]},
	])
}

test_matches_labelSelector {
	obj1 := {
		"kind": "Pod",
		"metadata": {
			"name": "frontend",
			"namespace": "default",
			"labels": {"foo": "bar"},
		},
		"spec": {"containers": [{"image": "nginx", "name": "nginx"}]},
	}

	not v1.matches_labelSelector(obj1, null)
	v1.matches_labelSelector({}, {})

	v1.matches_labelSelector({"metadata": {"labels": {"foo": "bar", "baz": "qux", "alpha": "bravo"}}}, {
		"matchExpressions": [
			{"key": "baz", "operator": "in", "values": ["qux"]},
			{"key": "foo", "operator": "in", "values": ["bar"]},
		],
		"matchLabels": {"alpha": "bravo"},
	})

	# missing matchLabels from object
	not v1.matches_labelSelector({"metadata": {"labels": {"foo": "bar", "baz": "qux"}}}, {
		"matchExpressions": [
			{"key": "baz", "operator": "in", "values": ["qux"]},
			{"key": "foo", "operator": "in", "values": ["bar"]},
		],
		"matchLabels": {"alpha": "bravo"},
	})

	# missing matchExpressions from object
	not v1.matches_labelSelector({"metadata": {"labels": {"foo": "baz", "baz": "qux", "alpha": "bravo"}}}, {
		"matchExpressions": [
			{"key": "baz", "operator": "in", "values": ["qux"]},
			{"key": "foo", "operator": "in", "values": ["bar"]},
		],
		"matchLabels": {"alpha": "bravo"},
	})
}

test_matches_networkPeer_simple {
	obj1 := {
		"kind": "Pod",
		"metadata": {
			"name": "frontend",
			"namespace": "default",
			"labels": {"foo": "bar"},
		},
		"spec": {"containers": [{"image": "nginx", "name": "nginx"}]},
	}

	not v1.matches_networkPeer(obj1, {"ipBlock": {"cidr": "172.17.0.0/16"}}, "foo")
	v1.matches_networkPeer(obj1, {"podSelector": {"matchLabels": {"foo": "bar"}}}, "default")
}

test_matches_networkPeer_namespaceSelector {
	prod1 := {"metadata": {"name": "prod1", "labels": {"type": "prod"}}}
	prod2 := {"metadata": {"name": "prod2", "labels": {"type": "prod"}}}
	dev1 := {"metadata": {"name": "dev1", "labels": {"type": "dev"}}}
	dev2 := {"metadata": {"name": "dev2", "labels": {"type": "dev"}}}
	peer := {"namespaceSelector": {"matchLabels": {"type": "prod"}}}
	not v1.matches_networkPeer(objects.nginxpod({"namespace": "default"}), peer, "foo") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	not v1.matches_networkPeer(objects.nginxpod({"namespace": "dev1"}), peer, "foo") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	v1.matches_networkPeer(objects.nginxpod({"namespace": "prod1"}), peer, "foo") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	v1.matches_networkPeer(objects.nginxpod({"namespace": "prod2"}), peer, "foo") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}
}

test_matches_networkPeer_podSelector {
	peer := {"podSelector": {"matchLabels": {"type": "prod"}}}
	not v1.matches_networkPeer(objects.nginxpod({"labels": {"type": "none"}}), peer, "foo")
	not v1.matches_networkPeer(objects.nginxpod({"labels": {"type": "prod"}, "namespace": "default"}), peer, "foo")
	v1.matches_networkPeer(objects.nginxpod({"labels": {"type": "prod"}, "namespace": "foo"}), peer, "foo")
}

test_matches_networkPeer_namespaceAndPodSelector {
	prod1 := {"metadata": {"name": "prod1", "labels": {"type": "prod"}}}
	prod2 := {"metadata": {"name": "prod2", "labels": {"type": "prod"}}}
	dev1 := {"metadata": {"name": "dev1", "labels": {"type": "dev"}}}
	dev2 := {"metadata": {"name": "dev2", "labels": {"type": "dev"}}}
	peer := {
		"namespaceSelector": {"matchLabels": {"type": "prod"}},
		"podSelector": {"matchLabels": {"owner": "alice"}},
	}

	v1.matches_networkPeer(objects.nginxpod({"labels": {"owner": "alice"}, "namespace": "prod1"}), peer, "nonexistent") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	# wrong pod label
	not v1.matches_networkPeer(objects.nginxpod({"labels": {"owner": "bob"}, "namespace": "prod1"}), peer, "nonexistent") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	# wrong namespace
	not v1.matches_networkPeer(objects.nginxpod({"labels": {"owner": "alice"}, "namespace": "dev1"}), peer, "nonexistent") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}

	# wrong pod label and wrong namespace
	not v1.matches_networkPeer(objects.nginxpod({"labels": {"owner": "bob"}, "namespace": "dev1"}), peer, "nonexistent") with data.kubernetes.resources.namespaces as {"prod1": prod1, "dev1": dev1, "prod2": prod2, "dev2": dev2}
}

test_matches_ingressSelector {
	ing := {"from": [
		{"namespaceSelector": {"matchLabels": {"type": "prod"}}},
		{"podSelector": {"matchLabels": {"owner": "alice"}}},
	]}

	ns := {"metadata": {"name": "prod1", "labels": {"type": "prod"}}}

	# corner cases
	v1.matches_ingressSelector(objects.nginxpod({"namespace": "default"}), {}, "foo")
	v1.matches_ingressSelector(objects.nginxpod({"namespace": "default"}), {"from": []}, "foo")

	# match podSelector (and default namespace)
	v1.matches_ingressSelector(objects.nginxpod({"namespace": "foo", "labels": {"owner": "alice"}}), ing, "foo")

	# match namespaceSelector
	v1.matches_ingressSelector(objects.nginxpod({"namespace": "prod1"}), ing, "foo") with data.kubernetes.resources.namespaces as {"prod1": ns}

	# match neither podSelector (neither labels nor namespace) nor namespaceSelector
	not v1.matches_ingressSelector(objects.nginxpod({"namespace": "foo"}), ing, "bar")

	# match neither podSelector (not labels but match namespace) nor namespaceSelector
	not v1.matches_ingressSelector(objects.nginxpod({"namespace": "foo"}), ing, "foo")
}

test_controlled_by_network_policy {
	netpol1 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol1",
			"namespace": "default",
		},
		"spec": {"podSelector": {"matchLabels": {"role": "db"}}},
	}

	netpol2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol2",
			"namespace": "default",
		},
		"spec": {"podSelector": {"matchExpressions": [{
			"key": "foo",
			"operator": "exists",
			"values": [],
		}]}},
	}

	obj1 := objects.nginxpod({"namespace": "default", "labels": {"foo": "bar"}})
	v1.controlled_by_network_policy(obj1) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol2": netpol2}
		with data.kubernetes.resources.pods["default"] as {"frontend": obj1}

	obj2 := objects.nginxpod({"namespace": "default", "labels": {"role": "db"}})
	v1.controlled_by_network_policy(obj2) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol2": netpol2}
		with data.kubernetes.resources.pods["default"] as {"frontend": obj2}

	obj3 := objects.nginxpod({"namespace": "default"})
	not v1.controlled_by_network_policy(obj3) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol2": netpol2}
		with data.kubernetes.resources.pods["default"] as {"frontend": obj3}
}

test_fill_out_metadata_for_template_inheritall {
	in := {"request": {
		"namespace": "bar",
		"object": {
			"metadata": {
				"name": "mydeployment",
				"namespace": "bar",
				"labels": {"data": "here"},
			},
			"spec": {"template": {"spec": {"metadata": {"foo": "bar"}}}},
		},
	}}

	actual := v1.fill_out_metadata_for_template(in.request.object.spec.template.spec) with input as in
	correct := {"metadata": {"foo": "bar", "name": "mydeployment", "namespace": "bar", "labels": {"data": "here"}}}
	actual == correct
}

test_fill_out_metadata_for_template_noinheritlabels {
	in := {"request": {
		"namespace": "bar",
		"object": {
			"metadata": {
				"name": "mydeployment",
				"namespace": "bar",
				"labels": {"data": "here"},
			},
			"spec": {"template": {"spec": {"metadata": {"foo": "bar", "labels": {"nowhere": "else"}}}}},
		},
	}}

	actual := v1.fill_out_metadata_for_template(in.request.object.spec.template.spec) with input as in
	correct := {"metadata": {"foo": "bar", "name": "mydeployment", "namespace": "bar", "labels": {"nowhere": "else"}}}
	actual == correct
}

test_fill_out_metadata_for_template_noinheritname {
	in := {"request": {
		"namespace": "bar",
		"object": {
			"metadata": {
				"name": "mydeployment",
				"namespace": "bar",
				"labels": {"data": "here"},
			},
			"spec": {"template": {"spec": {"metadata": {"foo": "bar", "name": "foo"}}}},
		},
	}}

	actual := v1.fill_out_metadata_for_template(in.request.object.spec.template.spec) with input as in
	correct := {"metadata": {"foo": "bar", "name": "foo", "namespace": "bar", "labels": {"data": "here"}}}
	actual == correct
}

test_fill_out_metadata_for_template_noinheritnamespace {
	in := {"request": {
		"namespace": "bar",
		"object": {
			"metadata": {
				"name": "mydeployment",
				"namespace": "bar",
				"labels": {"data": "here"},
			},
			"spec": {"template": {"spec": {"metadata": {"foo": "bar", "namespace": "default"}}}},
		},
	}}

	actual := v1.fill_out_metadata_for_template(in.request.object.spec.template.spec) with input as in
	correct := {"metadata": {"foo": "bar", "name": "mydeployment", "namespace": "default", "labels": {"data": "here"}}}
	actual == correct
}

test_fill_out_metadata {
	obj := {"metadata": {"name": "foo", "labels": "here"}, "spec": "whatever", "kind": "Pod", "apiVersion": "v1"}
	in := {"request": {"namespace": "bar", "object": obj}}
	actual := v1.fill_out_metadata(obj) with input as in
	correct := {
		"metadata": {"name": "foo", "namespace": "bar", "labels": "here"},
		"spec": "whatever",
		"kind": "Pod",
		"apiVersion": "v1",
	}

	actual == correct
}

test_incomplete_network_coverage_pod {
	netpol1 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol1",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/data": "true"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"acme.com/dmz": "true"}}}]}],
		},
	}

	# minimal object
	actual := v1.incomplete_network_coverage_pod with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginxpod({}))

	count(actual) == 1

	# with proper label
	actual2 := v1.incomplete_network_coverage_pod with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginxpod({"labels": {"acme.com/data": "true"}}))

	count(actual2) == 0

	# with unspecified namespace in metadata for pod
	in := {"request": {
		"kind": {"kind": "Pod"},
		"object": {
			"kind": "Pod",
			"metadata": {
				"name": "alpha",
				"labels": {"acme.com/data": "true"},
			},
			"spec": {"containers": [{"image": "nginx", "name": "nginx"}]},
		},
		"namespace": "default",
	}}

	actual3 := v1.incomplete_network_coverage_pod with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as in

	count(actual3) == 0
}

test_incomplete_network_coverage_template {
	netpol1 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol1",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/data": "true"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"acme.com/dmz": "true"}}}]}],
		},
	}

	# Deployment violation
	actual := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_uber({"kind": "Deployment"}))

	count(actual) == 1

	# Deployment safe
	actual2 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_uber({"labels": {"acme.com/data": "true"}, "kind": "Deployment"}))

	count(actual2) == 0

	# Statefulset violation
	actual3 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_statefulset({}))

	count(actual3) == 1

	# Statefulset safe
	actual4 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_statefulset({"labels": {"acme.com/data": "true"}}))

	count(actual4) == 0

	# Replicaset violation
	actual5 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_uber({"kind": "ReplicaSet"}))

	count(actual5) == 1

	# Replicaset safe
	actual6 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_uber({"labels": {"acme.com/data": "true"}, "kind": "ReplicaSet"}))

	count(actual6) == 0

	# DaemonSet violation
	actual7 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_daemonset({}))

	count(actual7) == 1

	# DaemonSet safe
	actual8 := v1.incomplete_network_coverage_template with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with input as objects.admission(objects.nginx_daemonset({"labels": {"acme.com/data": "true"}}))

	count(actual8) == 0
}

# TODO: think through how/if we want to really put these admission control policies
#    onto the DELETE operation.  If so, adjust policy-tester so the webhook is
#    configured to handle DELETEs too.
test_k8s_skip_incomplete_network_coverage_networkpolicy_delete {
	netpol_data := networkpolicy_ingress({"matchLabels": {"acme.com/data": "true"}}, {"name": "netpoldata"})

	netpol_data2 := networkpolicy_ingress({"matchLabels": {"acme.com/data": "true"}}, {"name": "netpoldata2"}) # same as netpol_data but with different name

	netpol_foo := networkpolicy_ingress({"matchLabels": {"foo": "true"}}, {"name": "netpol_foo"})

	pod_foo_data := objects.nginxpod({"name": "foo", "labels": {"acme.com/data": "true"}})

	# DELETE last policy
	actual := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_foo_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data}
		with input as objects.admission_op(netpol_data, {"operation": "DELETE"})

	count(actual) == 1

	# DELETE policy where others still cover
	actual2 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_foo_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data, "netpoldata2": netpol_data2}
		with input as objects.admission_op(netpol_data, {"operation": "DELETE"})

	count(actual2) == 0

	# # DELETE policy where others do not cover
	actual3 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_foo_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data, "netpolfoo": netpol_foo}
		with input as objects.admission_op(netpol_data, {"operation": "DELETE"})

	count(actual3) == 1
}

# TODO: for Update, need to adjust the policy-tester to (a) create the resource before loading policy
#   and then (b) load policy per normal and (c) run 'kubectl Apply'.  Though how we know what the value
#   was before I don't know--maybe just add a fake label.
test_k8s_skip_incomplete_network_coverage_networkpolicy_update {
	netpol_data := networkpolicy_ingress({"matchLabels": {"acme.com/data": "true"}}, {"name": "netpoldata"}) # matches on "data" label

	netpol_data2 := networkpolicy_ingress({"matchLabels": {"acme.com/data": "true"}}, {"name": "netpoldata2"}) # same as netpol_data but with different name

	netpol_data3 := networkpolicy_ingress({"matchLabels": {"acme.com/data": "true", "something": "else"}}, {"name": "netpoldata2"}) # same as netpol_data but with different name and extra label

	netpol_data_foo := networkpolicy_ingress({"matchLabels": {"foo": "true"}}, {"name": "netpoldata"}) # same as netpol_data but with different label (same name)

	netpol_foo := networkpolicy_ingress({"matchLabels": {"foo": "true"}}, {"name": "netpolfoo"}) # doesn't cover 'data' at all

	pod_data := objects.nginxpod({"name": "foo", "labels": {"acme.com/data": "true"}})

	# UPDATE policy without changing labels
	actual1 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data}
		with input as objects.admission_op(netpol_data2, {"operation": "UPDATE"})

	count(actual1) == 0

	# UPDATE policy and change labels current rule still ok
	actual2 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data}
		with input as objects.admission_op(netpol_data3, {"operation": "UPDATE"})

	count(actual2) == 0

	# UPDATE policy and change labels so current rule not ok
	actual3 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data}
		with input as objects.admission_op(netpol_data_foo, {"operation": "UPDATE"})

	count(actual3) == 1

	# UPDATE policy and change labels so not ok but others cover
	actual4 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data, "netpoldata2": netpol_data2}
		with input as objects.admission_op(netpol_data_foo, {"operation": "UPDATE"})

	count(actual4) == 0

	# UPDATE policy and change labels so not ok and others do not cover
	actual5 := v1.incomplete_network_coverage_networkpolicy with data.kubernetes.resources.pods["default"] as {"foo": pod_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpoldata": netpol_data, "netpolfoo": netpol_foo}
		with input as objects.admission_op(netpol_data_foo, {"operation": "UPDATE"})

	count(actual5) == 1
}

# TODO: run network_coverage_all over all of the tests for all its pieces
test_incomplete_network_coverage_all = true

networkpolicy_ingress(podSelector, params) = x {
	name := util.get(params, "name", "foo")
	namespace := util.get(params, "namespace", "default")
	from := util.get(params, "from", [])
	labels := util.get(params, "labels", {})
	x := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": name,
			"namespace": namespace,
			"labels": labels,
		},
		"spec": {
			"podSelector": podSelector,
			"ingress": [{"from": from}],
		},
	}
}

test_talks_to {
	obj1 := {
		"kind": "Pod",
		"metadata": {
			"name": "frontend",
			"namespace": "default",
			"labels": {"acme.com/dmz": "true"},
		},
		"spec": {"containers": [{"image": "nginx", "name": "nginx"}]},
	}

	obj2 := {
		"kind": "Pod",
		"metadata": {
			"name": "backend",
			"namespace": "default",
			"labels": {"acme.com/data": "true"},
		},
		"spec": {"containers": [{"image": "mysql", "name": "mysql"}]},
	}

	obj3 := {
		"kind": "Pod",
		"metadata": {
			"name": "backend",
			"namespace": "default",
			"labels": {"foo": "true"},
		},
		"spec": {"containers": [{"image": "mysql", "name": "mysql"}]},
	}

	netpol1 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol1",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/data": "true"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"acme.com/dmz": "true"}}}]}],
		},
	}

	# obj3 not controlled by any network policy
	v1.talks_to(obj1, obj3) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}

	# obj2 is controlled by network policy
	v1.controlled_by_network_policy(obj2) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}

	# obj1 matches ingress podSelector
	v1.talks_to(obj1, obj2) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}

	# obj2 fails to match ingress
	not v1.talks_to(obj3, obj2) with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
}

test_prohibited_communication_pod_labels {
	obj_dmz := {
		"kind": "Pod",
		"metadata": {
			"name": "frontend",
			"namespace": "default",
			"labels": {"acme.com/dmz": "true"},
		},
		"spec": {"containers": [{"image": "nginx", "name": "nginx"}]},
	}

	obj_data := {
		"kind": "Pod",
		"metadata": {
			"name": "backend",
			"namespace": "default",
			"labels": {"acme.com/data": "true"},
		},
		"spec": {"containers": [{"image": "mysql", "name": "mysql"}]},
	}

	obj_random := {
		"kind": "Pod",
		"metadata": {
			"name": "backend",
			"namespace": "default",
			"labels": {"foo": "true"},
		},
		"spec": {"containers": [{"image": "mysql", "name": "mysql"}]},
	}

	netpol1 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol1",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/data": "true"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"acme.com/dmz": "true"}}}]}],
		},
	}

	netpol2 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol2",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/dmz": "true"}},
			"ingress": [{"from": [{"ipBlock": "0.0.0.0"}]}],
		},
	}

	netpol3 := {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {
			"name": "netpol2",
			"namespace": "default",
		},
		"spec": {
			"podSelector": {"matchLabels": {"acme.com/dmz": "true"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"acme.com/data": "true"}}}]}],
		},
	}

	# prohibit data to talk to dmz (allowing dmz to talk to data)
	params := {"from": {"acme.com/data"}, "to": {"acme.com/dmz"}}

	# # obj1 matches ingress podSelector
	# v1.talks_to(obj_dmz, obj_data)
	#     with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
	# # obj2 fails to match ingress
	# not v1.talks_to(obj_random, obj_data)
	#     with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}

	# network policies are correct; create obj_dmz
	actual1 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_dmz)
		with data.kubernetes.resources.pods["default"] as {"backend": obj_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol2": netpol2}
		with data.library.parameters as params

	count(actual1) == 0

	# network policies are correct; create obj_data
	actual2 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_data)
		with data.kubernetes.resources.pods["default"] as {"frontend": obj_dmz}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol2": netpol2}
		with data.library.parameters as params

	count(actual2) == 0

	# network policies fail to cover dmz; create obj_dmz
	actual3 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_dmz)
		with data.kubernetes.resources.pods["default"] as {"backend": obj_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with data.library.parameters as params

	count(actual3) == 1

	# network policies fail to cover dmz; create obj_data
	actual4 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_data)
		with data.kubernetes.resources.pods["default"] as {"frontend": obj_dmz}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1}
		with data.library.parameters as params

	count(actual4) == 1

	# network policies cover dmz but allow too much; create obj_dmz
	actual5 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_dmz)
		with data.kubernetes.resources.pods["default"] as {"backend": obj_data}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol3": netpol3}
		with data.library.parameters as params

	count(actual5) == 1

	# network policies cover dmz but allow too much; create obj_data
	actual6 := v1.prohibited_communication_pod_labels with input as objects.admission(obj_data)
		with data.kubernetes.resources.pods["default"] as {"frontend": obj_dmz}
		with data.kubernetes.resources.networkpolicies["default"] as {"netpol1": netpol1, "netpol3": netpol3}
		with data.library.parameters as params

	count(actual6) == 1
}

# admission(obj) = admission_op(obj,{})
# admission_op (obj, params) = x {
#     smallobj := util.reduce_object_blacklist(obj, {"apiVersion"})
#     op := util.get(params, "operation", "CREATE")
#     x := {
#         "apiVersion": "v1",
#         "request": {
#             "kind": {"kind": util.get(obj, "kind", "Pod")},
#             "operation": op,
#             "namespace": util.get(util.get(obj, "metadata", {}), "namespace", "default"),
#             "object": smallobj
#         }
#     }
# }
# nginxpod(params) = x {
#     namespace := util.get(params, "namespace", "default")
#     labels := util.get(params, "labels", {})
#     name := util.get(params, "name", "frontend")
#     x := {
#         "apiVersion": "v1",
#         "kind": "Pod",
#         "metadata": {"name": name,
#                     "namespace": namespace,
#                     "labels": labels},
#         "spec": {
#             "containers": [
#                 {"image": "nginx", "name": "nginx"}
#         ]} }
# }
# nginx_uber(params) = x {
#     namespace := util.get(params, "namespace", "default")
#     labels := util.get(params, "labels", {})
#     name := util.get(params, "name", "frontend")
#     kind := util.get(params, "kind", "Deployment")
#     permitted_kinds := {"Deployment", "ReplicaSet",}
#     permitted_kinds[kind]
#     x := {
#         "apiVersion": "apps/v1",
#         "kind": kind,
#         "metadata": {"name": name,
#                     "namespace": namespace,
#                     "labels": labels},
#         "spec": {
#             "replicas": 2,
#             "selector": {
#                 "matchLabels": {"app": "nginx"}
#             },
#             "template": {
#                 "metadata": {
#                     "labels": util.merge_objects({"app": "nginx"}, labels),
#                 },
#                 "spec": {
#                     "containers": [{"image": "nginx", "name": "nginx"}]
#                 }
#             }
#         }}
# }
# nginx_statefulset(params) = x {
#     namespace := util.get(params, "namespace", "default")
#     labels := util.get(params, "labels", {})
#     name := util.get(params, "name", "frontend")
#     x := {
#         "apiVersion": "apps/v1",
#         "kind": "StatefulSet",
#         "metadata": {"name": name,
#                     "namespace": namespace,
#                     "labels": labels},
#         "spec": {
#             "replicas": 2,
#             "serviceName": "nginx",
#             "selector": {
#                 "matchLabels": {"app": "nginx"}
#             },
#             "template": {
#                 "metadata": {
#                     "labels": util.merge_objects({"app": "nginx"}, labels),
#                 },
#                 "spec": {
#                     "containers": [{"image": "nginx", "name": "nginx"}]
#                 }
#             }
#         }}
# }
# nginx_daemonset(params) = x {
#     namespace := util.get(params, "namespace", "default")
#     labels := util.get(params, "labels", {})
#     name := util.get(params, "name", "frontend")
#     x := {
#         "apiVersion": "apps/v1",
#         "kind": "DaemonSet",
#         "metadata": {"name": name,
#                     "namespace": namespace,
#                     "labels": labels},
#         "spec": {
#             "selector": {
#                 "matchLabels": {"app": "nginx"}
#             },
#             "template": {
#                 "metadata": {
#                     "labels": util.merge_objects({"app": "nginx"}, labels),
#                 },
#                 "spec": {
#                     "containers": [{"image": "nginx", "name": "nginx"}]
#                 }
#             }
#         }}
# }

test_k8s_pod_deny_host_namespace_sharing_bad {
	in := input_pod_with_args({"containers": {"nginx"}, "hostPID": true, "hostIPC": true})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) >= 1
}

test_k8s_pod_deny_host_namespace_sharing_good {
	in := input_pod_with_args({"containers": {"nginx"}})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) == 0
}

test_k8s_pod_deny_host_namespace_sharing_without_hostpid_good {
	in := input_pod_with_args({"containers": {"nginx"}})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) == 0
}

test_k8s_deployment_deny_host_namespace_sharing_bad {
	in := input_deployment_with_args({"containers": {"nginx"}, "hostPID": true, "hostIPC": true})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) >= 1
}

test_k8s_deployment_deny_host_namespace_sharing_good {
	in := input_deployment_with_args({"containers": {"nginx"}})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) == 0
}

test_k8s_replicaset_deny_host_namespace_sharing_bad {
	in := input_replicaset_with_args({"containers": {"nginx"}, "hostPID": true, "hostIPC": true})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) >= 1
}

test_k8s_replicaset_deny_host_namespace_sharing_good {
	in := input_replicaset_with_args({"containers": {"nginx"}})
	actual := v1.deny_host_namespace_sharing with input as in
	count(actual) == 0
}

input_pod_with_args(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	name := get(args, "name", "foo")
	regular_image_pull := get(args, "regular_image_pull", "IfNotPresent")
	init_image_pull := get(args, "init_image_pull", "IfNotPresent")
	hostPID := get(args, "hostPID", false)
	hostIPC := get(args, "hostIPC", false)
	containers := [{
		"image": image,
		"name": "nginx",
		"imagePullPolicy": regular_image_pull,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"imagePullPolicy": init_image_pull,
	} |
		init_images[image]
	]

	spec := {
		"containers": containers,
		"initContainers": initContainers,
		"hostPID": hostPID,
		"hostIPC": hostIPC,
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
				"metadata": {"name": name},
				"spec": spec,
			},
		},
	}
}

input_deployment_with_args(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	name := get(args, "name", "foo")
	regular_image_pull := get(args, "regular_image_pull", "IfNotPresent")
	init_image_pull := get(args, "init_image_pull", "IfNotPresent")
	hostPID := get(args, "hostPID", false)
	hostIPC := get(args, "hostIPC", false)
	containers := [{
		"image": image,
		"name": "nginx",
		"imagePullPolicy": regular_image_pull,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"imagePullPolicy": init_image_pull,
	} |
		init_images[image]
	]

	podspec := {
		"containers": containers,
		"initContainers": initContainers,
		"hostPID": hostPID,
		"hostIPC": hostIPC,
	}

	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"kind": {"kind": "Deployment"},
			"namespace": "prod",
			"object": {"spec": {
				"selector": {"matchLabels": {"app": "nginx"}},
				"replicas": 2,
				"template": {
					"metadata": {"name": name, "labels": {"app": "nginx"}},
					"spec": podspec,
				},
			}},
		},
	}
}

input_replicaset_with_args(args) = x {
	images := get(args, "containers", set())
	init_images := get(args, "initcontainers", set())
	name := get(args, "name", "foo")
	regular_image_pull := get(args, "regular_image_pull", "IfNotPresent")
	init_image_pull := get(args, "init_image_pull", "IfNotPresent")
	hostPID := get(args, "hostPID", false)
	hostIPC := get(args, "hostIPC", false)
	containers := [{
		"image": image,
		"name": "nginx",
		"imagePullPolicy": regular_image_pull,
	} |
		images[image]
	]

	initContainers := [{
		"image": image,
		"name": "bar",
		"imagePullPolicy": init_image_pull,
	} |
		init_images[image]
	]

	podspec := {
		"containers": containers,
		"initContainers": initContainers,
		"hostPID": hostPID,
		"hostIPC": hostIPC,
	}

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
					"spec": podspec,
				},
			}},
		},
	}
}

test_deny_loadbalancersourceranges_not_in_whitelist_1_good {
	parameters := {"whitelist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["2.2.2.0/24"])

	actual := v1.deny_loadbalancersourceranges_not_in_whitelist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 0
}

test_deny_loadbalancersourceranges_not_in_whitelist_2_good {
	parameters := {"whitelist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["2.2.2.128/25"])

	actual := v1.deny_loadbalancersourceranges_not_in_whitelist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 0
}

test_deny_loadbalancersourceranges_not_in_whitelist_3_bad {
	parameters := {"whitelist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["2.2.2.128/25", "3.3.4.0/24"])

	actual := v1.deny_loadbalancersourceranges_not_in_whitelist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 1
}

test_deny_loadbalancersourceranges_in_blacklist_4_good {
	parameters := {"blacklist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["4.2.2.0/24"])

	actual := v1.deny_loadbalancersourceranges_in_blacklist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 0
}

test_deny_loadbalancersourceranges_in_blacklist_5_bad {
	parameters := {"blacklist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["2.2.4.0/24", "3.3.3.128/25"])

	actual := v1.deny_loadbalancersourceranges_in_blacklist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 1
}

test_deny_loadbalancersourceranges_in_blacklist_6_bad {
	parameters := {"blacklist": ["2.2.2.0/24", "3.3.3.0/24", "1.1.1.0/24"]}
	input_request := objects.input_with_service("LoadBalancer", ["3.3.0.0/16"])

	actual := v1.deny_loadbalancersourceranges_in_blacklist with input as input_request
		with data.library.parameters as parameters

	count(actual) == 1
}

input_ingress_with_metadata(metadata) = x {
	x := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": metadata,
				"spec": {"rules": [{
					"host": "hello-world.info",
					"http": {"paths": [{
						"backend": {
							"serviceName": "web",
							"servicePort": 8080,
						},
						"path": "/",
					}]},
				}]},
			},
		},
	}
}

input_ingress_with_ingressclass(spec) = x {
	x := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": {"name": "foo"},
				"spec": spec,
			},
		},
	}
}

# with ingress-class annotation only.
test_k8s_deny_ingress_with_default_or_no_ingress_class_good_1 {
	annotations := {"kubernetes.io/ingress.class": "nginx-internal"}
	metadata := {
		"name": "foo",
		"annotations": annotations,
	}

	input_request := input_ingress_with_metadata(metadata)
	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 0
}

# without ingress-class annotation, without ingress-class.
test_k8s_deny_ingress_with_default_or_no_ingress_class_bad_1 {
	metadata := {"name": "foo"}

	input_request := input_ingress_with_metadata(metadata)
	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 1
}

# with blank value
test_k8s_deny_ingress_with_default_or_no_ingress_class_bad_2 {
	annotations := {"kubernetes.io/ingress.class": ""}

	metadata := {
		"name": "foo",
		"annotations": annotations,
	}

	input_request := input_ingress_with_metadata(metadata)
	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 1
}

# k8s version >=1.18, skipping these tests as they need 1.18 version(for policy-tester).
# with spec.ingressClassName
test_k8s_skip_deny_ingress_with_default_or_no_ingress_class_good_1_18_1 {
	spec := {
		"ingressClassName": "nginx",
		"rules": [{
			"host": "hello-world.info",
			"http": {"paths": [{
				"backend": {
					"serviceName": "web",
					"servicePort": 8080,
				},
				"path": "/",
			}]},
		}],
	}

	input_request := input_ingress_with_ingressclass(spec)
	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 0
}

# blank value of spec.ingressClassName
test_k8s_skip_deny_ingress_with_default_or_no_ingress_class_bad_1_18_2 {
	spec := {
		"ingressClassName": "",
		"rules": [{
			"host": "hello-world.info",
			"http": {"paths": [{
				"backend": {
					"serviceName": "web",
					"servicePort": 8080,
				},
				"path": "/",
			}]},
		}],
	}

	input_request := input_ingress_with_ingressclass(spec)
	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 1
}

# with spec.ingressClassName and annotation,
# the spec.ingressClassName should take precedence with k8s version >=1.18.
# and it will be an invalid request for k8s version <1.18.
test_k8s_skip_deny_ingress_with_default_or_no_ingress_class_bad_1_18_3 {
	spec := {
		"ingressClassName": "",
		"rules": [{
			"host": "hello-world.info",
			"http": {"paths": [{
				"backend": {
					"serviceName": "web",
					"servicePort": 8080,
				},
				"path": "/",
			}]},
		}],
	}

	annotations := {"kubernetes.io/ingress.class": "nginx-internal"}
	metadata := {
		"name": "foo",
		"annotations": annotations,
	}

	input_request := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": metadata,
				"spec": spec,
			},
		},
	}

	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 1
}

test_k8s_skip_deny_ingress_with_default_or_no_ingress_class_good_1_18_3 {
	spec := {
		"ingressClassName": "test-123",
		"rules": [{
			"host": "hello-world.info",
			"http": {"paths": [{
				"backend": {
					"serviceName": "web",
					"servicePort": 8080,
				},
				"path": "/",
			}]},
		}],
	}

	annotations := {"kubernetes.io/ingress.class": "nginx-internal"}
	metadata := {
		"name": "foo",
		"annotations": annotations,
	}

	input_request := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": metadata,
				"spec": spec,
			},
		},
	}

	actual := v1.deny_ingress_with_default_or_no_ingress_class with input as input_request

	count(actual) == 0
}

input_service_non_allowed_ports(port) = x {
	x := {
		"request": {
			"kind": {"kind": "Service"},
			"object": {
				"spec": {
					"selector": {"app": "MyApp"},
					"type": "ClusterIP",
					"ports": [
						{
							"protocol": "TCP",
							"name": "http",
							"port": port[0],
						},
						{
							"protocol": "TCP",
							"name": "https",
							"port": port[1],
						},
					],
				},
				"metadata": {"name": "my-service"},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "admission.k8s.io/v1beta1",
	}
}

test_k8s_restricts_service_ports_good_1 {
	parameters := {"port_numbers": ["80", "5000"]}
	in := input_service_non_allowed_ports([80, 5000])
	actual := v1.restricts_service_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 0
}

test_k8s_restricts_service_ports_bad_1 {
	parameters := {"port_numbers": ["80", "500"]}
	in := input_service_non_allowed_ports([80, 5000])
	actual := v1.restricts_service_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_k8s_restricts_service_ports_bad_2 {
	parameters := {"port_numbers": ["8080", "500"]}
	in := input_service_non_allowed_ports([80, 5000])
	actual := v1.restricts_service_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 2
}

input_container_non_allowed_ports(port) = x {
	x := {
		"request": {
			"kind": {"kind": "Pod"},
			"object": {
				"spec": {"containers": [
					{
						"name": "key-value-store",
						"image": "redis",
						"ports": [{"containerPort": port[0]}],
					},
					{
						"name": "frontend",
						"image": "django",
						"ports": [{"containerPort": port[1]}],
					},
				]},
				"metadata": {
					"name": "redis-django",
					"labels": {"app": "webapp"},
				},
			},
			"namespace": "foo",
			"operation": "CREATE",
		},
		"apiVersion": "v1",
	}
}

test_k8s_restricts_container_ports_good_1 {
	parameters := {"container_port_numbers": ["80", "500"]}
	in := input_container_non_allowed_ports([80, 500])
	actual := v1.restricts_container_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 0
}

test_k8s_restricts_container_ports_bad_1 {
	parameters := {"container_port_numbers": ["80", "5000"]}
	in := input_container_non_allowed_ports([80, 500])
	actual := v1.restricts_container_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_k8s_restricts_container_ports_bad_2 {
	parameters := {"container_port_numbers": ["8080", "500"]}
	in := input_container_non_allowed_ports([80, 5000])
	actual := v1.restricts_container_ports with input as in
		with data.library.parameters as parameters

	count(actual) == 2
}

# hostPorts PSP policy.
test_k8s_enforce_pod_hostports_whitelist_good {
	in := input_with_pod_with_hostPort
	p := {"host_port_ranges": ["1-8090"]}

	actual := v1.enforce_pod_hostports_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 0
}

test_k8s_enforce_pod_hostports_whitelist_bad {
	in := input_with_pod_with_hostPort
	p := {"host_port_ranges": ["1-50"]}

	actual := v1.enforce_pod_hostports_whitelist with data.library.parameters as p
		with input as in

	count(actual) == 2
}

input_with_pod_with_hostPort = x {
	x := {
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {
				"group": "",
				"kind": "Pod",
				"version": "v1",
			},
			"userinfo": {"username": "alice"},
			"operation": "CREATE",
			"namespace": "prod",
			"name": "nginx-host",
			"object": {
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"annotations": null,
					"name": "nginx-host",
					"namespace": "prod",
				},
				"spec": {
					"initContainers": [{
						"image": "nginx",
						"name": "nginx-1",
						"ports": [{
							"containerPort": 8090,
							"hostPort": 8090,
							"protocol": "TCP",
						}],
					}],
					"containers": [{
						"image": "nginx",
						"imagePullPolicy": "IfNotPresent",
						"name": "nginx-host",
						"ports": [{
							"containerPort": 8080,
							"hostPort": 8080,
							"protocol": "TCP",
						}],
					}],
					"securityContext": {},
					"volumes": [],
				},
			},
		},
	}
}

input_kubectl_exec_allowed_commands(command) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"dryRun": false,
			"kind": {
				"group": "",
				"kind": "PodExecOptions",
				"version": "v1",
			},
			"name": "nginx",
			"namespace": "default",
			"object": {
				"apiVersion": "v1",
				"command": command,
				"container": "nginx",
				"kind": "PodExecOptions",
				"stdin": true,
				"stdout": true,
				"tty": true,
			},
			"oldObject": null,
			"operation": "CONNECT",
			"options": null,
			"requestKind": {
				"group": "",
				"kind": "PodExecOptions",
				"version": "v1",
			},
			"requestResource": {
				"group": "",
				"resource": "pods",
				"version": "v1",
			},
			"requestSubResource": "exec",
			"resource": {
				"group": "",
				"resource": "pods",
				"version": "v1",
			},
			"subResource": "exec",
			"uid": "44ebfd4d-5a34-480e-965f-4080ae608a9a",
			"userInfo": {
				"groups": [
					"system:masters",
					"system:authenticated",
				],
				"username": "minikube-user",
			},
		},
	}
}

test_whitelist_exec_commands_good_1 {
	parameters := {"allowed_commands": ["sh", "date"]}
	in := input_kubectl_exec_allowed_commands(["sh", "date"])
	actual := v1.whitelist_exec_commands with input as in
		with data.library.parameters as parameters

	count(actual) == 0
}

test_whitelist_exec_commands_bad_1 {
	parameters := {"allowed_commands": ["sh", "date1"]}
	in := input_kubectl_exec_allowed_commands(["sh", "date"])
	actual := v1.whitelist_exec_commands with input as in
		with data.library.parameters as parameters

	count(actual) == 1
}

test_whitelist_exec_commands_bad_2 {
	parameters := {"allowed_commands": ["sh1", "date1"]}
	in := input_kubectl_exec_allowed_commands(["sh", "date"])
	actual := v1.whitelist_exec_commands with input as in
		with data.library.parameters as parameters

	count(actual) == 2
}

input_with_ingress_annoatations(annotations) = x {
	x := {
		"kind": "AdmissionReview",
		"apiVersion": "admission.k8s.io/v1beta1",
		"request": {
			"kind": {
				"group": "networking.k8s.io",
				"version": "v1beta1",
				"kind": "Ingress",
			},
			"namespace": "prod",
			"operation": "CREATE",
			"object": {
				"metadata": {
					"name": "foo",
					"annotations": annotations,
				},
				"spec": {"rules": [{"http": {"paths": [{
					"path": "/icons",
					"pathType": "ImplementationSpecific",
					"backend": {"resource": {
						"apiGroup": "k8s.example.com",
						"kind": "StorageBucket",
						"name": "icon-assets",
					}},
				}]}}]},
			},
		},
	}
}

test_k8s_deny_ingress_with_custom_snippet_annotation_good {
	annotations := {"nginx.ingress.kubernetes.io/rewrite-target": "/"}

	in := input_with_ingress_annoatations(annotations)
	actual := v1.deny_ingress_with_custom_snippet_annotation with input as in
	count(actual) == 0
}

test_k8s_deny_ingress_with_custom_snippet_annotation_bad1 {
	annotations := {"nginx.ingress.kubernetes.io/configuration-snippet": "more_set_headers \"Request-Id: $req_id\";\n"}
	in := input_with_ingress_annoatations(annotations)
	actual := v1.deny_ingress_with_custom_snippet_annotation with input as in
	count(actual) == 1
}

test_k8s_deny_ingress_with_custom_snippet_annotation_bad2 {
	annotations := {"nginx.ingress.kubernetes.io/server-snippet": "set $agentflag 0;\n\nif ($http_user_agent ~* \"(Mobile)\" ){\n  set $agentflag 1;\n}\n\nif ( $agentflag = 1 ) {\n  return 301 https://m.example.com;\n}\n"}
	in := input_with_ingress_annoatations(annotations)
	actual := v1.deny_ingress_with_custom_snippet_annotation with input as in

	count(actual) == 1
}
