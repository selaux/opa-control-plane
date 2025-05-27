package library.v1.kubernetes.admission.encryption.test_v1

import data.library.v1.kubernetes.admission.encryption.v1
import data.library.v1.kubernetes.admission.test_objects.v1 as objects

test_deny_identity_provider_second_identity {
	in := input_encryption_config("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 0
}

test_deny_identity_provider_secrets_first_identity {
	in := input_encryption_config_secrets("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 1
}

test_deny_identity_provider_secrets_second_identity {
	in := input_encryption_config_secrets_second("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 0
}

test_check_kms_encryptionconfig_ok {
	in := input_encryption_config_secrets_no_identity("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 0
}

test_check_kms_encryptionconfig_no_kms {
	in := input_encryption_config_no_kms("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 0
}

test_check_kms_encryptionconfig_last_only {
	in := input_encryption_config_only_identity("name", "endpoint")

	actual := v1.deny_identity_provider with input as in

	count(actual) == 1
}

input_encryption_config_only_identity(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [{"identity": {}}],
			}]},
		},
	}
}

input_encryption_config_no_kms(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [
					{"other": {
						"name": name,
						"endpoint": endpoint,
						"cachesize": 100,
						"timeout": "3s",
					}},
					{"identity": {}},
				],
			}]},
		},
	}
}

input_encryption_config(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["other"],
				"providers": [
					{"kms": {
						"name": name,
						"endpoint": endpoint,
						"cachesize": 100,
						"timeout": "3s",
					}},
					{"identity": {}},
				],
			}]},
		},
	}
}

input_encryption_config_secrets_second(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [
					{"kms": {
						"name": name,
						"endpoint": endpoint,
						"cachesize": 100,
						"timeout": "3s",
					}},
					{"identity": {}},
				],
			}]},
		},
	}
}

input_encryption_config_secrets(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [
					{"identity": {}},
					{"kms": {
						"name": name,
						"endpoint": endpoint,
						"cachesize": 100,
						"timeout": "3s",
					}},
				],
			}]},
		},
	}
}

input_encryption_config_secrets_no_identity(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [{"kms": {
					"name": name,
					"endpoint": endpoint,
					"cachesize": 100,
					"timeout": "3s",
				}}],
			}]},
		},
	}
}

test_check_kms_encryptionconfig_no_parameter_ok {
	in := input_encryption_config("name", "endpoint")

	actual := v1.check_kms_encryptionconfig with input as in

	count(actual) == 0
}

test_check_kms_encryptionconfig_no_identity_ok {
	in := input_encryption_config_no_identity("name", "endpoint")

	actual := v1.check_kms_encryptionconfig with input as in

	count(actual) == 0
}

test_check_kms_encryptionconfig_no_kms_fail {
	in := input_encryption_config_no_kms_only("name", "endpoint")

	actual := v1.check_kms_encryptionconfig with input as in

	count(actual) == 1
}

test_check_kms_encryptionconfig_identity_first_fail {
	in := input_encryption_config_identity_first("name", "endpoint")
	actual := v1.check_kms_encryptionconfig with input as in
	count(actual) == 1
}

test_check_kms_encryptionconfig_not_in_whitelist_fail_key {
	in := input_encryption_config("name", "endpoint")
	p := {"approved_kms_configs": {"notexist": {"endpoint"}}}
	actual := v1.check_kms_encryptionconfig with input as in
		with data.library.parameters as p

	count(actual) == 1
}

test_check_kms_encryptionconfig_not_in_whitelist_fail_value {
	in := input_encryption_config("name", "endpoint")
	p := {"approved_kms_configs": {"name": {"notexist"}}}
	actual := v1.check_kms_encryptionconfig with input as in with data.library.parameters as p
	count(actual) == 1
}

test_check_kms_encryptionconfig_ok {
	in := input_encryption_config("name", "endpoint")
	p := {"approved_kms_configs": {"name": {"endpoint"}}}
	actual := v1.check_kms_encryptionconfig with input as in with data.library.parameters as p
	count(actual) == 0
}

input_encryption_config_identity_first(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [
					{"identity": {}},
					{"kms": {
						"name": name,
						"endpoint": endpoint,
						"cachesize": 100,
						"timeout": "3s",
					}},
				],
			}]},
		},
	}
}

input_encryption_config_no_identity(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [{"kms": {
					"name": name,
					"endpoint": endpoint,
					"cachesize": 100,
					"timeout": "3s",
				}}],
			}]},
		},
	}
}

input_encryption_config_no_kms_only(name, endpoint) = x {
	x := {
		"apiVersion": "admission.k8s.io/v1beta1",
		"kind": "AdmissionReview",
		"request": {
			"kind": {"kind": "EncryptionConfiguration"},
			"object": {"resources": [{
				"resources": ["secrets"],
				"providers": [{"identity": {}}],
			}]},
		},
	}
}
