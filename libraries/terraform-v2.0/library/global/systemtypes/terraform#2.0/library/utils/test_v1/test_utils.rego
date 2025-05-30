package global.systemtypes["terraform:2.0"].library.utils.test_v1

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

test_plan_resource_changes {
	test_input := {"resource_changes": [
		{
			"change": {"after": {"bucket": "bucket1"}},
			"name": "bucket1",
			"type": "aws_s3_bucket",
		},
		{
			"change": {
				"actions": [],
				"after": {"bucket": "bucket2"},
			},
			"name": "bucket2",
			"type": "aws_s3_bucket",
		},
		{
			"change": {
				"actions": ["update"],
				"after": {"bucket": "bucket3"},
			},
			"name": "bucket3",
			"type": "aws_s3_bucket",
		},
		{
			"change": {
				"actions": ["create", "delete"],
				"after": {"bucket": "bucket4"},
			},
			"name": "bucket4",
			"type": "aws_s3_bucket",
		},
		{
			"change": {
				"actions": ["delete"],
				"after": {"bucket": "bucket5"},
			},
			"name": "bucket5",
			"type": "aws_s3_bucket",
		},
	]}

	actual := utils.plan_resource_changes with input as test_input
	actual == {
		{"change": {"actions": [], "after": {"bucket": "bucket2"}}, "name": "bucket2", "type": "aws_s3_bucket"},
		{"change": {"actions": ["create", "delete"], "after": {"bucket": "bucket4"}}, "name": "bucket4", "type": "aws_s3_bucket"},
		{"change": {"actions": ["update"], "after": {"bucket": "bucket3"}}, "name": "bucket3", "type": "aws_s3_bucket"},
		{"change": {"after": {"bucket": "bucket1"}}, "name": "bucket1", "type": "aws_s3_bucket"},
	}
}

test_build_metadata_return_all_data_present {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := ["do", "re", "mi"]
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": context,
		},
	}
}

test_build_metadata_return_no_meta {
	meta := null
	params := ["do", "re", "mi"]
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": null,
			"title": null,
			"severity": null,
			"resource_category": null,
			"control_category": null,
			"rule_link": null,
			"compliance_pack": null,
			"description": null,
			"impact": null,
			"remediation": null,
			"platform": null,
			"provider": null,
			"rule_targets": null,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": context,
		},
	}
}

test_build_metadata_return_empty_meta {
	meta := {}
	params := ["do", "re", "mi"]
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": null,
			"title": null,
			"severity": null,
			"resource_category": null,
			"control_category": null,
			"rule_link": null,
			"compliance_pack": null,
			"description": null,
			"impact": null,
			"remediation": null,
			"platform": null,
			"provider": null,
			"rule_targets": null,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": context,
		},
	}
}

test_build_metadata_return_bad_type_meta {
	meta := "oops"
	params := ["do", "re", "mi"]
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": null,
			"title": null,
			"severity": null,
			"resource_category": null,
			"control_category": null,
			"rule_link": null,
			"compliance_pack": null,
			"description": null,
			"impact": null,
			"remediation": null,
			"platform": null,
			"provider": null,
			"rule_targets": null,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": context,
		},
	}
}

test_build_metadata_return_no_resource {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := ["do", "re", "mi"]
	resource := null
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": null,
			"address": null,
			"name": null,
			"actions": null,
			"context": context,
		},
	}
}

test_build_metadata_return_empty_resource {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := ["do", "re", "mi"]
	resource := {}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": null,
			"address": null,
			"name": null,
			"actions": null,
			"context": context,
		},
	}
}

test_build_metadata_return_bad_type_resource {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := ["do", "re", "mi"]
	resource := 1337
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": null,
			"address": null,
			"name": null,
			"actions": null,
			"context": context,
		},
	}
}

test_build_metadata_return_no_params {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := null
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := {"foo": "bar"}
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": null,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": context,
		},
	}
}

test_build_metadata_return_no_context {
	meta := {
		"title": "My Title",
		"description": "My description",
		"custom": {
			"id": "my_id",
			"severity": "OH_MY",
			"resource_category": "test-category",
			"control_category": "test-control",
			"rule_link": "https://docs.styra.com/systems/terraform/snippets",
			"impact": "heavy",
			"remediation": "Call someone",
			"platform": {"name": "My Platform"},
			"provider": {"name": "My Provider"},
			"rule_targets": {
				"service": "two",
				"name": "three",
				"identifier": "one_two_three",
				"argument": "foobar",
			},
		},
	}
	params := ["do", "re", "mi"]
	resource := {
		"type": "one_two_three",
		"address": "one_two_three.four",
		"name": "four",
		"change": {"actions": ["create"]},
	}
	context := null
	ret := utils.build_metadata_return(meta, params, resource, context)

	ret == {
		"rule": {
			"id": meta.custom.id,
			"title": meta.title,
			"severity": meta.custom.severity,
			"resource_category": meta.custom.resource_category,
			"control_category": meta.custom.control_category,
			"rule_link": meta.custom.rule_link,
			"compliance_pack": null,
			"description": meta.description,
			"impact": meta.custom.impact,
			"remediation": meta.custom.remediation,
			"platform": meta.custom.platform.name,
			"provider": meta.custom.provider.name,
			"rule_targets": meta.custom.rule_targets,
			"parameters": params,
		},
		"resource": {
			"module": "root_module",
			"type": resource.type,
			"address": resource.address,
			"name": resource.name,
			"actions": resource.change.actions,
			"context": null,
		},
	}
}
