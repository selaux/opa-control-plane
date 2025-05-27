package library.v1.kubernetes.admission.audit.test_v1

import data.library.v1.kubernetes.admission.audit.v1

test_audit_sink_good_no_webhook {
	in := input_audit_sink_config_no_webhook("q", "b")
	actual := v1.require_auditsink with input as in

	count(actual) == 0
}

test_audit_sink_good_with_webhook {
	in := input_audit_sink_config("https://audit.app")
	actual := v1.require_auditsink with input as in

	count(actual) == 0
}

test_audit_sink_bad_with_webhook {
	in := input_audit_sink_config("http://audit.app")
	actual := v1.require_auditsink with input as in

	count(actual) == 1
}

input_audit_sink_config_no_webhook(user, group) = x {
	x = {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"userInfo": {"username": user, "group": group},
			"kind": {"kind": "AuditSink"},
			"object": {
				"metadata": {"name": "mysink"},
				"spec": {"policy": {
					"level": "Metadata",
					"stages": ["ResponseComplete"],
				}},
			},
		},
	}
}

input_audit_sink_config(url) = x {
	x = {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"operation": "CREATE",
			"userInfo": {"username": "user", "group": "group"},
			"kind": {"kind": "AuditSink"},
			"object": {
				"metadata": {"name": "mysink"},
				"spec": {
					"policy": {
						"level": "Metadata",
						"stages": ["ResponseComplete"],
					},
					"webhook": {
						"throttle": {
							"qps": 10,
							"burst": 15,
						},
						"clientConfig": {"url": url},
					},
				},
			},
		},
	}
}
