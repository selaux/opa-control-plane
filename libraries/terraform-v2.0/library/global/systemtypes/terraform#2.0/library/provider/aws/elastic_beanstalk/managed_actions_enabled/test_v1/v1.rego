package global.systemtypes["terraform:2.0"].library.provider.aws.elastic_beanstalk.managed_actions_enabled.test_v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.elastic_beanstalk.managed_actions_enabled.v1

test_managed_actions_enabled_elastic_beanstalk_good {
	enabled := "true"
	in := input_elastic_beanstalk(enabled)
	actual := v1.disabled_managed_actions_is_prohibited with input as in
	count(actual) == 0
}

test_managed_actions_enabled_elastic_beanstalk_bad {
	enabled := "false"
	in := input_elastic_beanstalk(enabled)
	actual := v1.disabled_managed_actions_is_prohibited with input as in
	count(actual) == 1
}

test_managed_actions_enabled_elastic_beanstalk_good {
	enabled := true
	in := input_elastic_beanstalk(enabled)
	actual := v1.disabled_managed_actions_is_prohibited with input as in
	count(actual) == 0
}

test_managed_actions_enabled_elastic_beanstalk_bad {
	enabled := false
	in := input_elastic_beanstalk(enabled)
	actual := v1.disabled_managed_actions_is_prohibited with input as in
	count(actual) == 1
}

test_managed_actions_enabled_elastic_beanstalk_missing_settings {
	in := input_managed_actions_enabled_setting_missing
	actual := v1.disabled_managed_actions_is_prohibited with input as in
	count(actual) == 1
}

input_elastic_beanstalk(value) = x {
	x := {
		"format_version": "1.1",
		"terraform_version": "1.3.7",
		"variables": {"region": {"value": "us-west-2"}},
		"planned_values": {"root_module": {"resources": [
			{
				"address": "aws_elastic_beanstalk_application.ebs_app",
				"mode": "managed",
				"type": "aws_elastic_beanstalk_application",
				"name": "ebs_app",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"appversion_lifecycle": [],
					"description": "terraform application for elastic beanstalk",
					"name": "beanstalk-application",
					"tags": null,
				},
				"sensitive_values": {
					"appversion_lifecycle": [],
					"tags_all": {},
				},
			},
			{
				"address": "aws_elastic_beanstalk_environment.ebs_env",
				"mode": "managed",
				"type": "aws_elastic_beanstalk_environment",
				"name": "ebs_env",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 1,
				"values": {
					"application": "beanstalk-application",
					"description": null,
					"name": "tf-test-name",
					"poll_interval": null,
					"setting": [
						{
							"name": "IamInstanceProfile",
							"namespace": "aws:autoscaling:launchconfiguration",
							"resource": "",
							"value": "beanstalk-ec2-user",
						},
						{
							"name": "InstanceRefreshEnabled",
							"namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
							"resource": "",
							"value": "true",
						},
						{
							"name": "ManagedActionsEnabled",
							"namespace": "aws:elasticbeanstalk:managedactions",
							"resource": "",
							"value": value,
						},
						{
							"name": "PreferredStartTime",
							"namespace": "aws:elasticbeanstalk:managedactions",
							"resource": "",
							"value": "MON:02:00",
						},
						{
							"name": "ServiceRole",
							"namespace": "aws:elasticbeanstalk:environment",
							"resource": "",
						},
						{
							"name": "ServiceRoleForManagedUpdates",
							"namespace": "aws:elasticbeanstalk:managedactions",
							"resource": "",
						},
						{
							"name": "SystemType",
							"namespace": "aws:elasticbeanstalk:healthreporting:system",
							"resource": "",
							"value": "enhanced",
						},
						{
							"name": "UpdateLevel",
							"namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
							"resource": "",
							"value": "Patch",
						},
					],
					"solution_stack_name": "64bit Amazon Linux 2 v3.5.2 running Go 1",
					"tags": null,
					"template_name": null,
					"tier": "WebServer",
					"wait_for_ready_timeout": "20m",
				},
				"sensitive_values": {
					"all_settings": [],
					"autoscaling_groups": [],
					"instances": [],
					"launch_configurations": [],
					"load_balancers": [],
					"queues": [],
					"setting": [
						{},
						{},
						{},
						{},
						{},
						{},
						{},
						{},
					],
					"tags_all": {},
					"triggers": [],
				},
			},
			{
				"address": "aws_iam_instance_profile.beanstalk_ec2",
				"mode": "managed",
				"type": "aws_iam_instance_profile",
				"name": "beanstalk_ec2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"name": "beanstalk-ec2-user",
					"name_prefix": null,
					"path": "/",
					"role": "beanstalk-service-role",
					"tags": null,
				},
				"sensitive_values": {"tags_all": {}},
			},
			{
				"address": "aws_iam_instance_profile.beanstalk_service",
				"mode": "managed",
				"type": "aws_iam_instance_profile",
				"name": "beanstalk_service",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"name": "beanstalk-service-user",
					"name_prefix": null,
					"path": "/",
					"role": "beanstalk-service-role",
					"tags": null,
				},
				"sensitive_values": {"tags_all": {}},
			},
			{
				"address": "aws_iam_role.eb_service_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "eb_service_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"elasticbeanstalk.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "beanstalk-service-role",
					"path": "/",
					"permissions_boundary": null,
					"tags": {"Environment": "default"},
					"tags_all": {"Environment": "default"},
				},
				"sensitive_values": {
					"inline_policy": [],
					"managed_policy_arns": [],
					"tags": {},
					"tags_all": {},
				},
			},
			{
				"address": "aws_iam_role_policy_attachment.eb_service_role",
				"mode": "managed",
				"type": "aws_iam_role_policy_attachment",
				"name": "eb_service_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"policy_arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService",
					"role": "beanstalk-service-role",
				},
				"sensitive_values": {},
			},
			{
				"address": "aws_iam_role_policy_attachment.eb_service_role_2",
				"mode": "managed",
				"type": "aws_iam_role_policy_attachment",
				"name": "eb_service_role_2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"policy_arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
					"role": "beanstalk-service-role",
				},
				"sensitive_values": {},
			},
		]}},
		"resource_changes": [
			{
				"address": "aws_elastic_beanstalk_application.ebs_app",
				"mode": "managed",
				"type": "aws_elastic_beanstalk_application",
				"name": "ebs_app",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"appversion_lifecycle": [],
						"description": "terraform application for elastic beanstalk",
						"name": "beanstalk-application",
						"tags": null,
					},
					"after_unknown": {
						"appversion_lifecycle": [],
						"arn": true,
						"id": true,
						"tags_all": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"appversion_lifecycle": [],
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_elastic_beanstalk_environment.ebs_env",
				"mode": "managed",
				"type": "aws_elastic_beanstalk_environment",
				"name": "ebs_env",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"application": "beanstalk-application",
						"description": null,
						"name": "tf-test-name",
						"poll_interval": null,
						"setting": [
							{
								"name": "IamInstanceProfile",
								"namespace": "aws:autoscaling:launchconfiguration",
								"resource": "",
								"value": "beanstalk-ec2-user",
							},
							{
								"name": "InstanceRefreshEnabled",
								"namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
								"resource": "",
								"value": "true",
							},
							{
								"name": "ManagedActionsEnabled",
								"namespace": "aws:elasticbeanstalk:managedactions",
								"resource": "",
								"value": value,
							},
							{
								"name": "PreferredStartTime",
								"namespace": "aws:elasticbeanstalk:managedactions",
								"resource": "",
								"value": "MON:02:00",
							},
							{
								"name": "ServiceRole",
								"namespace": "aws:elasticbeanstalk:environment",
								"resource": "",
							},
							{
								"name": "ServiceRoleForManagedUpdates",
								"namespace": "aws:elasticbeanstalk:managedactions",
								"resource": "",
							},
							{
								"name": "SystemType",
								"namespace": "aws:elasticbeanstalk:healthreporting:system",
								"resource": "",
								"value": "enhanced",
							},
							{
								"name": "UpdateLevel",
								"namespace": "aws:elasticbeanstalk:managedactions:platformupdate",
								"resource": "",
								"value": "Patch",
							},
						],
						"solution_stack_name": "64bit Amazon Linux 2 v3.5.2 running Go 1",
						"tags": null,
						"template_name": null,
						"tier": "WebServer",
						"wait_for_ready_timeout": "20m",
					},
					"after_unknown": {
						"all_settings": true,
						"arn": true,
						"autoscaling_groups": true,
						"cname": true,
						"cname_prefix": true,
						"endpoint_url": true,
						"id": true,
						"instances": true,
						"launch_configurations": true,
						"load_balancers": true,
						"platform_arn": true,
						"queues": true,
						"setting": [
							{},
							{},
							{},
							{},
							{"value": true},
							{"value": true},
							{},
							{},
						],
						"tags_all": true,
						"triggers": true,
						"version_label": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"all_settings": [],
						"autoscaling_groups": [],
						"instances": [],
						"launch_configurations": [],
						"load_balancers": [],
						"queues": [],
						"setting": [
							{},
							{},
							{},
							{},
							{},
							{},
							{},
							{},
						],
						"tags_all": {},
						"triggers": [],
					},
				},
			},
			{
				"address": "aws_iam_instance_profile.beanstalk_ec2",
				"mode": "managed",
				"type": "aws_iam_instance_profile",
				"name": "beanstalk_ec2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"name": "beanstalk-ec2-user",
						"name_prefix": null,
						"path": "/",
						"role": "beanstalk-service-role",
						"tags": null,
					},
					"after_unknown": {
						"arn": true,
						"create_date": true,
						"id": true,
						"tags_all": true,
						"unique_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"tags_all": {}},
				},
			},
			{
				"address": "aws_iam_instance_profile.beanstalk_service",
				"mode": "managed",
				"type": "aws_iam_instance_profile",
				"name": "beanstalk_service",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"name": "beanstalk-service-user",
						"name_prefix": null,
						"path": "/",
						"role": "beanstalk-service-role",
						"tags": null,
					},
					"after_unknown": {
						"arn": true,
						"create_date": true,
						"id": true,
						"tags_all": true,
						"unique_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {"tags_all": {}},
				},
			},
			{
				"address": "aws_iam_role.eb_service_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "eb_service_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"elasticbeanstalk.amazonaws.com\"},\"Sid\":\"\"}],\"Version\":\"2012-10-17\"}",
						"description": null,
						"force_detach_policies": false,
						"max_session_duration": 3600,
						"name": "beanstalk-service-role",
						"path": "/",
						"permissions_boundary": null,
						"tags": {"Environment": "default"},
						"tags_all": {"Environment": "default"},
					},
					"after_unknown": {
						"arn": true,
						"create_date": true,
						"id": true,
						"inline_policy": true,
						"managed_policy_arns": true,
						"name_prefix": true,
						"tags": {},
						"tags_all": {},
						"unique_id": true,
					},
					"before_sensitive": false,
					"after_sensitive": {
						"inline_policy": [],
						"managed_policy_arns": [],
						"tags": {},
						"tags_all": {},
					},
				},
			},
			{
				"address": "aws_iam_role_policy_attachment.eb_service_role",
				"mode": "managed",
				"type": "aws_iam_role_policy_attachment",
				"name": "eb_service_role",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"policy_arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService",
						"role": "beanstalk-service-role",
					},
					"after_unknown": {"id": true},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
			{
				"address": "aws_iam_role_policy_attachment.eb_service_role_2",
				"mode": "managed",
				"type": "aws_iam_role_policy_attachment",
				"name": "eb_service_role_2",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {
						"policy_arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
						"role": "beanstalk-service-role",
					},
					"after_unknown": {"id": true},
					"before_sensitive": false,
					"after_sensitive": {},
				},
			},
		],
		"prior_state": {
			"format_version": "1.0",
			"terraform_version": "1.3.7",
			"values": {"root_module": {"resources": [
				{
					"address": "data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth",
					"mode": "data",
					"type": "aws_iam_policy",
					"name": "AWSElasticBeanstalkEnhancedHealth",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
						"description": "AWS Elastic Beanstalk Service policy for Health Monitoring system",
						"id": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
						"name": "AWSElasticBeanstalkEnhancedHealth",
						"path": "/service-role/",
						"path_prefix": null,
						"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"elasticloadbalancing:DescribeInstanceHealth\",\n        \"elasticloadbalancing:DescribeLoadBalancers\",\n        \"elasticloadbalancing:DescribeTargetHealth\",\n        \"ec2:DescribeInstances\",\n        \"ec2:DescribeInstanceStatus\",\n        \"ec2:GetConsoleOutput\",\n        \"ec2:AssociateAddress\",\n        \"ec2:DescribeAddresses\",\n        \"ec2:DescribeSecurityGroups\",\n        \"sqs:GetQueueAttributes\",\n        \"sqs:GetQueueUrl\",\n        \"autoscaling:DescribeAutoScalingGroups\",\n        \"autoscaling:DescribeAutoScalingInstances\",\n        \"autoscaling:DescribeScalingActivities\",\n        \"autoscaling:DescribeNotificationConfigurations\",\n        \"sns:Publish\"\n      ],\n      \"Resource\": [\n        \"*\"\n      ]\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"logs:DescribeLogStreams\",\n        \"logs:CreateLogStream\",\n        \"logs:PutLogEvents\"\n      ],\n      \"Resource\": \"arn:aws:logs:*:*:log-group:/aws/elasticbeanstalk/*:log-stream:*\"\n    }\n  ]\n}\n\n",
						"policy_id": "ANPAIH5EFJNMOGUUTKLFE",
						"tags": {},
					},
					"sensitive_values": {"tags": {}},
				},
				{
					"address": "data.aws_iam_policy.AWSElasticBeanstalkService",
					"mode": "data",
					"type": "aws_iam_policy",
					"name": "AWSElasticBeanstalkService",
					"provider_name": "registry.terraform.io/hashicorp/aws",
					"schema_version": 0,
					"values": {
						"arn": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService",
						"description": "This policy is on a deprecation path. See documentation for guidance: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/iam-servicerole.html. AWS Elastic Beanstalk Service role policy which grants permissions to create & manage resources (i.e.: AutoScaling, EC2, S3, CloudFormation, ELB, etc.) on your behalf.",
						"id": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService",
						"name": "AWSElasticBeanstalkService",
						"path": "/service-role/",
						"path_prefix": null,
						"policy": "{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"AllowCloudformationOperationsOnElasticBeanstalkStacks\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"cloudformation:*\"\n            ],\n            \"Resource\": [\n                \"arn:aws:cloudformation:*:*:stack/awseb-*\",\n                \"arn:aws:cloudformation:*:*:stack/eb-*\"\n            ]\n        },\n        {\n            \"Sid\": \"AllowDeleteCloudwatchLogGroups\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"logs:DeleteLogGroup\"\n            ],\n            \"Resource\": [\n                \"arn:aws:logs:*:*:log-group:/aws/elasticbeanstalk*\"\n            ]\n        },\n        {\n            \"Sid\": \"AllowS3OperationsOnElasticBeanstalkBuckets\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"s3:*\"\n            ],\n            \"Resource\": [\n                \"arn:aws:s3:::elasticbeanstalk-*\",\n                \"arn:aws:s3:::elasticbeanstalk-*/*\"\n            ]\n        },\n        {\n            \"Sid\": \"AllowLaunchTemplateRunInstances\",\n            \"Effect\": \"Allow\",\n            \"Action\": \"ec2:RunInstances\",\n            \"Resource\": \"*\",\n            \"Condition\": {\n                \"ArnLike\": {\n                    \"ec2:LaunchTemplate\": \"arn:aws:ec2:*:*:launch-template/*\"\n                }\n            }\n        },\n        {\n            \"Sid\": \"AllowOperations\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"autoscaling:AttachInstances\",\n                \"autoscaling:CreateAutoScalingGroup\",\n                \"autoscaling:CreateLaunchConfiguration\",\n                \"autoscaling:DeleteLaunchConfiguration\",\n                \"autoscaling:DeleteAutoScalingGroup\",\n                \"autoscaling:DeleteScheduledAction\",\n                \"autoscaling:DescribeAccountLimits\",\n                \"autoscaling:DescribeAutoScalingGroups\",\n                \"autoscaling:DescribeAutoScalingInstances\",\n                \"autoscaling:DescribeLaunchConfigurations\",\n                \"autoscaling:DescribeLoadBalancers\",\n                \"autoscaling:DescribeNotificationConfigurations\",\n                \"autoscaling:DescribeScalingActivities\",\n                \"autoscaling:DescribeScheduledActions\",\n                \"autoscaling:DetachInstances\",\n                \"autoscaling:DeletePolicy\",\n                \"autoscaling:PutScalingPolicy\",\n                \"autoscaling:PutScheduledUpdateGroupAction\",\n                \"autoscaling:PutNotificationConfiguration\",\n                \"autoscaling:ResumeProcesses\",\n                \"autoscaling:SetDesiredCapacity\",\n                \"autoscaling:SuspendProcesses\",\n                \"autoscaling:TerminateInstanceInAutoScalingGroup\",\n                \"autoscaling:UpdateAutoScalingGroup\",\n                \"cloudwatch:PutMetricAlarm\",\n                \"ec2:AssociateAddress\",\n                \"ec2:AllocateAddress\",\n                \"ec2:AuthorizeSecurityGroupEgress\",\n                \"ec2:AuthorizeSecurityGroupIngress\",\n                \"ec2:CreateLaunchTemplate\",\n                \"ec2:CreateLaunchTemplateVersion\",\n                \"ec2:DescribeLaunchTemplates\",\n                \"ec2:DescribeLaunchTemplateVersions\",\n                \"ec2:DeleteLaunchTemplate\",\n                \"ec2:DeleteLaunchTemplateVersions\",\n                \"ec2:CreateSecurityGroup\",\n                \"ec2:DeleteSecurityGroup\",\n                \"ec2:DescribeAccountAttributes\",\n                \"ec2:DescribeAddresses\",\n                \"ec2:DescribeImages\",\n                \"ec2:DescribeInstances\",\n                \"ec2:DescribeKeyPairs\",\n                \"ec2:DescribeSecurityGroups\",\n                \"ec2:DescribeSnapshots\",\n                \"ec2:DescribeSubnets\",\n                \"ec2:DescribeVpcs\",\n                \"ec2:DescribeInstanceAttribute\",\n                \"ec2:DescribeSpotInstanceRequests\",\n                \"ec2:DescribeVpcClassicLink\",\n                \"ec2:DisassociateAddress\",\n                \"ec2:ReleaseAddress\",\n                \"ec2:RevokeSecurityGroupEgress\",\n                \"ec2:RevokeSecurityGroupIngress\",\n                \"ec2:TerminateInstances\",\n                \"ecs:CreateCluster\",\n                \"ecs:DeleteCluster\",\n                \"ecs:DescribeClusters\",\n                \"ecs:RegisterTaskDefinition\",\n                \"elasticbeanstalk:*\",\n                \"elasticloadbalancing:ApplySecurityGroupsToLoadBalancer\",\n                \"elasticloadbalancing:ConfigureHealthCheck\",\n                \"elasticloadbalancing:CreateLoadBalancer\",\n                \"elasticloadbalancing:DeleteLoadBalancer\",\n                \"elasticloadbalancing:DeregisterInstancesFromLoadBalancer\",\n                \"elasticloadbalancing:DescribeInstanceHealth\",\n                \"elasticloadbalancing:DescribeLoadBalancers\",\n                \"elasticloadbalancing:DescribeTargetHealth\",\n                \"elasticloadbalancing:RegisterInstancesWithLoadBalancer\",\n                \"elasticloadbalancing:DescribeTargetGroups\",\n                \"elasticloadbalancing:RegisterTargets\",\n                \"elasticloadbalancing:DeregisterTargets\",\n                \"iam:ListRoles\",\n                \"iam:PassRole\",\n                \"logs:CreateLogGroup\",\n                \"logs:PutRetentionPolicy\",\n                \"logs:DescribeLogGroups\",\n                \"rds:DescribeDBEngineVersions\",\n                \"rds:DescribeDBInstances\",\n                \"rds:DescribeOrderableDBInstanceOptions\",\n                \"s3:GetObject\",\n                \"s3:GetObjectAcl\",\n                \"s3:ListBucket\",\n                \"sns:CreateTopic\",\n                \"sns:GetTopicAttributes\",\n                \"sns:ListSubscriptionsByTopic\",\n                \"sns:Subscribe\",\n                \"sns:SetTopicAttributes\",\n                \"sqs:GetQueueAttributes\",\n                \"sqs:GetQueueUrl\",\n                \"codebuild:CreateProject\",\n                \"codebuild:DeleteProject\",\n                \"codebuild:BatchGetBuilds\",\n                \"codebuild:StartBuild\"\n            ],\n            \"Resource\": [\n                \"*\"\n            ]\n        }\n    ]\n}",
						"policy_id": "ANPAJKQ5SN74ZQ4WASXBM",
						"tags": {},
					},
					"sensitive_values": {"tags": {}},
				},
			]}},
		},
		"configuration": {
			"provider_config": {"aws": {
				"name": "aws",
				"full_name": "registry.terraform.io/hashicorp/aws",
				"version_constraint": "~> 4.0",
				"expressions": {"region": {"references": ["var.region"]}},
			}},
			"root_module": {
				"resources": [
					{
						"address": "aws_elastic_beanstalk_application.ebs_app",
						"mode": "managed",
						"type": "aws_elastic_beanstalk_application",
						"name": "ebs_app",
						"provider_config_key": "aws",
						"expressions": {
							"description": {"constant_value": "terraform application for elastic beanstalk"},
							"name": {"constant_value": "beanstalk-application"},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_elastic_beanstalk_environment.ebs_env",
						"mode": "managed",
						"type": "aws_elastic_beanstalk_environment",
						"name": "ebs_env",
						"provider_config_key": "aws",
						"expressions": {
							"application": {"references": [
								"aws_elastic_beanstalk_application.ebs_app.name",
								"aws_elastic_beanstalk_application.ebs_app",
							]},
							"name": {"constant_value": "tf-test-name"},
							"setting": [
								{
									"name": {"constant_value": "ServiceRole"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:environment"},
									"resource": {"constant_value": ""},
									"value": {"references": [
										"aws_iam_role.eb_service_role.arn",
										"aws_iam_role.eb_service_role",
									]},
								},
								{
									"name": {"constant_value": "IamInstanceProfile"},
									"namespace": {"constant_value": "aws:autoscaling:launchconfiguration"},
									"value": {"references": [
										"aws_iam_instance_profile.beanstalk_ec2.name",
										"aws_iam_instance_profile.beanstalk_ec2",
									]},
								},
								{
									"name": {"constant_value": "SystemType"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:healthreporting:system"},
									"resource": {"constant_value": ""},
									"value": {"constant_value": "enhanced"},
								},
								{
									"name": {"constant_value": "ManagedActionsEnabled"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:managedactions"},
									"resource": {"constant_value": ""},
									"value": {"constant_value": "true"},
								},
								{
									"name": {"constant_value": "PreferredStartTime"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:managedactions"},
									"resource": {"constant_value": ""},
									"value": {"constant_value": "MON:02:00"},
								},
								{
									"name": {"constant_value": "ServiceRoleForManagedUpdates"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:managedactions"},
									"resource": {"constant_value": ""},
									"value": {"references": [
										"aws_iam_role.eb_service_role.arn",
										"aws_iam_role.eb_service_role",
									]},
								},
								{
									"name": {"constant_value": "UpdateLevel"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:managedactions:platformupdate"},
									"resource": {"constant_value": ""},
									"value": {"constant_value": "Patch"},
								},
								{
									"name": {"constant_value": "InstanceRefreshEnabled"},
									"namespace": {"constant_value": "aws:elasticbeanstalk:managedactions:platformupdate"},
									"resource": {"constant_value": ""},
									"value": {"constant_value": "true"},
								},
							],
							"solution_stack_name": {"constant_value": "64bit Amazon Linux 2 v3.5.2 running Go 1"},
						},
						"schema_version": 1,
					},
					{
						"address": "aws_iam_instance_profile.beanstalk_ec2",
						"mode": "managed",
						"type": "aws_iam_instance_profile",
						"name": "beanstalk_ec2",
						"provider_config_key": "aws",
						"expressions": {
							"name": {"constant_value": "beanstalk-ec2-user"},
							"role": {"references": [
								"aws_iam_role.eb_service_role.name",
								"aws_iam_role.eb_service_role",
							]},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_iam_instance_profile.beanstalk_service",
						"mode": "managed",
						"type": "aws_iam_instance_profile",
						"name": "beanstalk_service",
						"provider_config_key": "aws",
						"expressions": {
							"name": {"constant_value": "beanstalk-service-user"},
							"role": {"references": [
								"aws_iam_role.eb_service_role.name",
								"aws_iam_role.eb_service_role",
							]},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_iam_role.eb_service_role",
						"mode": "managed",
						"type": "aws_iam_role",
						"name": "eb_service_role",
						"provider_config_key": "aws",
						"expressions": {
							"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"elasticbeanstalk.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
							"name": {"constant_value": "beanstalk-service-role"},
							"tags": {"references": ["terraform.workspace"]},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_iam_role_policy_attachment.eb_service_role",
						"mode": "managed",
						"type": "aws_iam_role_policy_attachment",
						"name": "eb_service_role",
						"provider_config_key": "aws",
						"expressions": {
							"policy_arn": {"references": [
								"data.aws_iam_policy.AWSElasticBeanstalkService.arn",
								"data.aws_iam_policy.AWSElasticBeanstalkService",
							]},
							"role": {"references": [
								"aws_iam_role.eb_service_role.name",
								"aws_iam_role.eb_service_role",
							]},
						},
						"schema_version": 0,
					},
					{
						"address": "aws_iam_role_policy_attachment.eb_service_role_2",
						"mode": "managed",
						"type": "aws_iam_role_policy_attachment",
						"name": "eb_service_role_2",
						"provider_config_key": "aws",
						"expressions": {
							"policy_arn": {"references": [
								"data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth.arn",
								"data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth",
							]},
							"role": {"references": [
								"aws_iam_role.eb_service_role.name",
								"aws_iam_role.eb_service_role",
							]},
						},
						"schema_version": 0,
					},
					{
						"address": "data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth",
						"mode": "data",
						"type": "aws_iam_policy",
						"name": "AWSElasticBeanstalkEnhancedHealth",
						"provider_config_key": "aws",
						"expressions": {"arn": {"constant_value": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"}},
						"schema_version": 0,
					},
					{
						"address": "data.aws_iam_policy.AWSElasticBeanstalkService",
						"mode": "data",
						"type": "aws_iam_policy",
						"name": "AWSElasticBeanstalkService",
						"provider_config_key": "aws",
						"expressions": {"arn": {"constant_value": "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService"}},
						"schema_version": 0,
					},
				],
				"variables": {"region": {"default": "us-west-2"}},
			},
		},
		"relevant_attributes": [
			{
				"resource": "aws_iam_instance_profile.beanstalk_ec2",
				"attribute": ["name"],
			},
			{
				"resource": "data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth",
				"attribute": ["arn"],
			},
			{
				"resource": "data.aws_iam_policy.AWSElasticBeanstalkService",
				"attribute": ["arn"],
			},
			{
				"resource": "aws_iam_role.eb_service_role",
				"attribute": ["name"],
			},
			{
				"resource": "aws_elastic_beanstalk_application.ebs_app",
				"attribute": ["name"],
			},
			{
				"resource": "aws_iam_role.eb_service_role",
				"attribute": ["arn"],
			},
		],
	}
}

input_managed_actions_enabled_setting_missing = {
	"format_version": "1.1",
	"terraform_version": "1.2.2",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_elastic_beanstalk_environment.ebs_env",
		"mode": "managed",
		"type": "aws_elastic_beanstalk_environment",
		"name": "ebs_env",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"schema_version": 1,
		"values": {
			"application": "beanstalk-application",
			"description": null,
			"name": "tf-test-name",
			"poll_interval": null,
			"setting": [
				{
					"name": "IamInstanceProfile",
					"namespace": "aws:autoscaling:launchconfiguration",
					"resource": "",
					"value": "beanstalk-ec2-user",
				},
				{
					"name": "ServiceRole",
					"namespace": "aws:elasticbeanstalk:environment",
					"resource": "",
				},
			],
			"solution_stack_name": "64bit Amazon Linux 2 v3.5.2 running Go 1",
			"tags": null,
			"template_name": null,
			"tier": "WebServer",
			"wait_for_ready_timeout": "20m",
		},
		"sensitive_values": {
			"all_settings": [],
			"autoscaling_groups": [],
			"instances": [],
			"launch_configurations": [],
			"load_balancers": [],
			"queues": [],
			"setting": [
				{},
				{},
			],
			"tags_all": {},
			"triggers": [],
		},
	}]}},
	"resource_changes": [{
		"address": "aws_elastic_beanstalk_environment.ebs_env",
		"mode": "managed",
		"type": "aws_elastic_beanstalk_environment",
		"name": "ebs_env",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"application": "beanstalk-application",
				"description": null,
				"name": "tf-test-name",
				"poll_interval": null,
				"setting": [
					{
						"name": "IamInstanceProfile",
						"namespace": "aws:autoscaling:launchconfiguration",
						"resource": "",
						"value": "beanstalk-ec2-user",
					},
					{
						"name": "ServiceRole",
						"namespace": "aws:elasticbeanstalk:environment",
						"resource": "",
					},
				],
				"solution_stack_name": "64bit Amazon Linux 2 v3.5.2 running Go 1",
				"tags": null,
				"template_name": null,
				"tier": "WebServer",
				"wait_for_ready_timeout": "20m",
			},
			"after_unknown": {
				"all_settings": true,
				"arn": true,
				"autoscaling_groups": true,
				"cname": true,
				"cname_prefix": true,
				"endpoint_url": true,
				"id": true,
				"instances": true,
				"launch_configurations": true,
				"load_balancers": true,
				"platform_arn": true,
				"queues": true,
				"setting": [
					{},
					{"value": true},
				],
				"tags_all": true,
				"triggers": true,
				"version_label": true,
			},
			"before_sensitive": false,
			"after_sensitive": {
				"all_settings": [],
				"autoscaling_groups": [],
				"instances": [],
				"launch_configurations": [],
				"load_balancers": [],
				"queues": [],
				"setting": [
					{},
					{},
				],
				"tags_all": {},
				"triggers": [],
			},
		},
	}],
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"full_name": "registry.terraform.io/hashicorp/aws",
			"version_constraint": "~> 3.27",
			"expressions": {
				"profile": {"constant_value": "default"},
				"region": {"references": ["var.region"]},
			},
		}},
		"root_module": {
			"resources": [{
				"address": "aws_elastic_beanstalk_environment.ebs_env",
				"mode": "managed",
				"type": "aws_elastic_beanstalk_environment",
				"name": "ebs_env",
				"provider_config_key": "aws",
				"expressions": {
					"application": {"references": [
						"aws_elastic_beanstalk_application.ebs_app.name",
						"aws_elastic_beanstalk_application.ebs_app",
					]},
					"name": {"constant_value": "tf-test-name"},
					"setting": [
						{
							"name": {"constant_value": "ServiceRole"},
							"namespace": {"constant_value": "aws:elasticbeanstalk:environment"},
							"resource": {"constant_value": ""},
							"value": {"references": [
								"aws_iam_role.eb_service_role.arn",
								"aws_iam_role.eb_service_role",
							]},
						},
						{
							"name": {"constant_value": "IamInstanceProfile"},
							"namespace": {"constant_value": "aws:autoscaling:launchconfiguration"},
							"value": {"references": [
								"aws_iam_instance_profile.beanstalk_ec2.name",
								"aws_iam_instance_profile.beanstalk_ec2",
							]},
						},
					],
					"solution_stack_name": {"constant_value": "64bit Amazon Linux 2 v3.5.2 running Go 1"},
				},
				"schema_version": 1,
			}],
			"variables": {"region": {"default": "us-west-2"}},
		},
	},
}
