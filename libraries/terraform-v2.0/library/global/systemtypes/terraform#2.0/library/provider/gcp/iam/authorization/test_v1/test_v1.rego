package global.systemtypes["terraform:2.0"].library.provider.gcp.iam.authorization.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.gcp.iam.authorization.v1 as authorization

############################
# unit tests
test_prohibit_service_account_with_admin_privileges_good_owner_role {
	member_config = {"condition": [], "member": "user:jane@example.com", "project": "your-project-id", "role": "roles/owner"}
	in = input_with_google_project_iam_member_resource(member_config)
	actual := authorization.prohibit_service_account_with_admin_privileges with input as in
	count(actual) == 0
}

test_prohibit_service_account_with_admin_privileges_good_editor_role {
	member_config = {"condition": [], "member": "user:jane@example.com", "project": "your-project-id", "role": "roles/editor"}
	in = input_with_google_project_iam_member_resource(member_config)
	actual := authorization.prohibit_service_account_with_admin_privileges with input as in
	count(actual) == 0
}

test_prohibit_service_account_with_admin_privileges_bad_editor_role {
	member_config = {"condition": [], "member": "user:jane@example.gserviceaccount.com", "project": "your-project-id", "role": "roles/editor"}
	in = input_with_google_project_iam_member_resource(member_config)
	actual := authorization.prohibit_service_account_with_admin_privileges with input as in
	count(actual) == 1
}

test_prohibit_service_account_with_admin_privileges_bad_owner_role {
	member_config = {"condition": [], "member": "user:jane@example.gserviceaccount.com", "project": "your-project-id", "role": "roles/owner"}
	in = input_with_google_project_iam_member_resource(member_config)
	actual := authorization.prohibit_service_account_with_admin_privileges with input as in
	count(actual) == 1
}

#################
# test input data
input_with_google_project_iam_member_resource(member_config) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.15",
		"planned_values": {"root_module": {"resources": [{
			"address": "google_project_iam_member.project",
			"mode": "managed",
			"type": "google_project_iam_member",
			"name": "project",
			"provider_name": "google",
			"schema_version": 0,
			"values": member_config,
		}]}},
		"resource_changes": [{
			"address": "google_project_iam_member.project",
			"mode": "managed",
			"type": "google_project_iam_member",
			"name": "project",
			"provider_name": "google",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": member_config,
				"after_unknown": {
					"condition": [],
					"etag": true,
					"id": true,
				},
			},
		}],
		"configuration": {"root_module": {"resources": [{
			"address": "google_project_iam_member.project",
			"mode": "managed",
			"type": "google_project_iam_member",
			"name": "project",
			"provider_config_key": "google",
			"expressions": {
				"member": {"constant_value": "user:jane@developer.gserviceaccount.com"},
				"project": {"constant_value": "your-project-id"},
				"role": {"constant_value": "roles/owner"},
			},
			"schema_version": 0,
		}]}},
	}
}
