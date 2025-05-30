package global.systemtypes["terraform:2.0"].library.provider.aws.util.v1

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# Helper rules for AWS resources in the resource_changes plan object

api_gateway_rest_api_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_api_gateway_rest_api"
}

apigatewayv2_api_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_apigatewayv2_api"
}

autoscaling_group_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_autoscaling_group"
}

cloudfront_distribution_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_cloudfront_distribution"
}

cloudtrail_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_cloudtrail"
}

codebuild_project_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_codebuild_project"
}

dax_cluster_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_dax_cluster"
}

dms_replication_instance_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_dms_replication_instance"
}

dynamodb_table_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_dynamodb_table"
}

ebs_volume_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ebs_volume"
}

ebs_snapshot_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ebs_snapshot"
}

ec2_instance_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_instance"
}

ecr_repository_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ecr_repository"
}

ecs_service_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ecs_service"
}

ecs_task_definition_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ecs_task_definition"
}

efs_file_system_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_efs_file_system"
}

elastic_beanstalk_environment_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_elastic_beanstalk_environment"
}

elasticsearch_domain_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_elasticsearch_domain"
}

elb_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_elb"
}

guardduty_detector_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_guardduty_detector"
}

iam_account_password_policy_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_account_password_policy"
}

iam_any_policy_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == all_iam_policy_types[_]
}

iam_group_policy_attachment_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_group_policy_attachment"
}

iam_policy_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_policy"
}

iam_role_policy_attachment_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_role_policy_attachment"
}

iam_user_policy_attachment_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_user_policy_attachment"
}

iam_user_policy_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_iam_user_policy"
}

kinesis_stream_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_kinesis_stream"
}

lambda_permission_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_lambda_permission"
}

launch_configuration_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_launch_configuration"
}

launch_template_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_launch_template"
}

opensearch_domain_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_opensearch_domain"
}

rds_cluster_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_rds_cluster"
}

db_instance_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_db_instance"
}

redshift_cluster_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_redshift_cluster"
}

s3_bucket_logging_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_logging"
}

s3_bucket_object_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_object"
}

s3_bucket_policy_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_policy"
}

s3_bucket_public_access_block_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
}

s3_bucket_acl_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_acl"
}

s3_bucket_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket"
}

s3_bucket_server_side_encryption_configuration_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
}

s3_bucket_versioning_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_bucket_versioning"
}

s3_object_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_s3_object"
}

sagemaker_notebook_instance_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_sagemaker_notebook_instance"
}

secretsmanager_secret_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_secretsmanager_secret"
}

security_group_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_security_group"
}

security_group_rule_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_security_group_rule"
}

sns_topic_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_sns_topic"
}

sqs_queue_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_sqs_queue"
}

ssm_document_resource_changes[resource] {
	resource := utils.plan_resource_changes[_]
	resource.type == "aws_ssm_document"
}

# Data resources

# iam_policy_document_data_sources[data_source] {
# 	data_source := utils.data_sources[_]
# 	data_source.type == "aws_iam_policy_document"
# }

# Configuration resources

ec2_instance_conf_resources[resource] {
	resource := utils.plan_configuration[_]
	resource.type == "aws_instance"
}

ebs_snapshot_conf_resources[resource] {
	resource := utils.plan_configuration[_]
	resource.type == "aws_ebs_snapshot"
}

s3_bucket_logging_conf_resources[resource] {
	resource := utils.plan_configuration[_]
	resource.type == "aws_s3_bucket_logging"
}

s3_bucket_server_side_encryption_configuration_conf_resources[resource] {
	resource := utils.plan_configuration[_]
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
}

s3_bucket_versioning_conf_resources[resource] {
	resource := utils.plan_configuration[_]
	resource.type == "aws_s3_bucket_versioning"
}

# All iam policy types
all_iam_policy_types := ["aws_iam_user_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_policy"]
