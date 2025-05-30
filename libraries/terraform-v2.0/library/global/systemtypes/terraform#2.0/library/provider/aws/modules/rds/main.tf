resource "aws_db_instance" "default" {
  allocated_storage                   = 10
  engine                              = "mysql"
  engine_version                      = "5.7"
  instance_class                      = "db.t3.micro"
  db_name                             = "mydb"
  username                            = "foo"
  password                            = "foobarbaz"
  parameter_group_name                = "default.mysql5.7"
  skip_final_snapshot                 = true
  auto_minor_version_upgrade          = true
  publicly_accessible                 = true
  #iam_database_authentication_enabled = true
  #enabled_cloudwatch_logs_exports     = ["audit"]
}

resource "aws_rds_cluster" "default" {
  cluster_identifier                  = "aurora-cluster-demo"
  engine                              = "aurora-mysql"
  engine_version                      = "5.7.mysql_aurora.2.03.2"
  availability_zones                  = ["us-west-1a", "us-west-1b", "us-west-1c"]
  database_name                       = "mydb"
  master_username                     = "foo"
  master_password                     = "bar"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  #iam_database_authentication_enabled = true
}
