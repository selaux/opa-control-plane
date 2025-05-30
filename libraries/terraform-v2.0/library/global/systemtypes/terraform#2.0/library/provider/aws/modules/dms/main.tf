resource "aws_dms_replication_subnet_group" "dms_subnet_group" {
  replication_subnet_group_description = "Test replication subnet group"
  replication_subnet_group_id          = "test-dms-replication-subnet-group-tf"

  subnet_ids = [
    "subnet-0e83c6f472f6fd98e",
  ]

  tags = {
    Name = "DMS subnet group"
  }
}

# Create a new replication instance
resource "aws_dms_replication_instance" "tf_dms" {
  allocated_storage            = 20
  apply_immediately            = true
  auto_minor_version_upgrade   = true
  availability_zone            = "us-west-2c"
  engine_version               = "3.4.6"
  kms_key_arn                  = "arn:aws:kms:us-west-2:546653085803:key/9a1d5407-5450-4449-be1a-531348fd9aca"
  multi_az                     = false
  preferred_maintenance_window = "sun:10:30-sun:14:30"
  publicly_accessible          = true # change this to false to make this private
  replication_instance_class   = "dms.t3.medium"
  replication_instance_id      = "test-dms-replication-instance-tf"
  replication_subnet_group_id  = aws_dms_replication_subnet_group.dms_subnet_group.id
  tags = {
    Name = "MyInstance"
  }


  depends_on = [
    aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role,
    aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole,
    aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole
  ]
}
