package global.systemtypes["terraform:2.0"].library.provider.aws.iam.restricted_policy.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.iam.restricted_policy.v1

test_restricted_iam_policy_good {
	policy := "{\"Statement\":[{\"Action\":[\"s3:BypassGovernanceRetention\",\"s3:CreateBucket\",\"s3:CreateJob\",\"s3:DeleteAccessPoint\"],\"Effect\":\"Allow\",\"Resource\":\"arn:aws:s3:::styra-onprem-test01\",\"Sid\":\"Stmt1616762744855\"}],\"Version\":\"2012-10-17\"}"
	in := input_iam_policy(policy)
	actual := v1.restricted_iam_policy with input as in
	count(actual) == 0
}

test_restricted_iam_policy_actions_has_asterisk {
	policy := "{\"Statement\":[{\"Action\":\"s3:*\",\"Effect\":\"Allow\",\"Resource\":\"arn:aws:s3:::sample_bucket\",\"Sid\":\"Stmt1617793414694\"}],\"Version\":\"2012-10-17\"}"
	in := input_iam_policy(policy)
	actual := v1.restricted_iam_policy with input as in
	count(actual) == 1
}

test_restricted_iam_policy_only_asterisk_in_resource {
	policy := "{\"Statement\":[{\"Action\":[\"s3:CreateAccessPoint\",\"s3:CreateAccessPointForObjectLambda\",\"s3:CreateBucket\",\"s3:CreateJob\",\"s3:DeleteAccessPoint\",\"s3:DeleteBucket\",\"s3:DeleteBucketOwnershipControls\"],\"Effect\":\"Allow\",\"Resource\":\"*\",\"Sid\":\"Stmt1617792876977\"}],\"Version\":\"2012-10-17\"}"
	in := input_iam_policy(policy)
	actual := v1.restricted_iam_policy with input as in
	count(actual) == 1
}

test_restricted_iam_policy_bad {
	policy := "{\"Statement\":[{\"Action\":\"s3:*\",\"Effect\":\"Allow\",\"Resource\":[\"arn:aws:s3:::sample_bucket/*\",\"*\"],\"Sid\":\"Stmt1617792009095\"}],\"Version\":\"2012-10-17\"}"
	in := input_iam_policy(policy)
	actual := v1.restricted_iam_policy with input as in
	count(actual) == 2
}

input_iam_policy(policy) = x {
	x := {
		"format_version": "0.1",
		"terraform_version": "0.12.30",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_iam_policy.new_iam_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "new_iam_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "An IAM policy that has overly broad permissions",
				"name": "new_iam_policy",
				"name_prefix": null,
				"path": "/",
				"policy": policy,
				"tags": null,
			},
		}]}},
		"resource_changes": [{
			"address": "aws_iam_policy.new_iam_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "new_iam_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "An IAM policy that has overly broad permissions",
					"name": "new_iam_policy",
					"name_prefix": null,
					"path": "/",
					"policy": policy,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"policy_id": true,
				},
			},
		}],
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"expressions": {
					"profile": {"constant_value": "tf-example"},
					"region": {"constant_value": "us-east-1"},
				},
			}},
			"root_module": {"resources": [{
				"address": "aws_iam_policy.new_iam_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "new_iam_policy",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "An IAM policy that has overly broad permissions"},
					"name": {"constant_value": "new_iam_policy"},
					"path": {"constant_value": "/"},
					"policy": {},
				},
				"schema_version": 0,
			}]},
		},
	}
}
