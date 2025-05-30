resource "aws_elastic_beanstalk_application" "ebs_app" {
  name        = "beanstalk-application"
  description = "terraform application for elastic beanstalk"
}

resource "aws_iam_instance_profile" "beanstalk_service" {
  name = "beanstalk-service-user"
  role = aws_iam_role.eb_service_role.name
}

resource "aws_iam_instance_profile" "beanstalk_ec2" {
  name = "beanstalk-ec2-user"
  role = aws_iam_role.eb_service_role.name
}

resource "aws_elastic_beanstalk_environment" "ebs_env" {
  name                = "tf-test-name"
  application         = aws_elastic_beanstalk_application.ebs_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.5.2 running Go 1"
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "ServiceRole"
    value     = aws_iam_role.eb_service_role.arn
    resource  = ""
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.beanstalk_ec2.name
  }
  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "SystemType"
    value     = "enhanced"
    resource  = ""
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "ManagedActionsEnabled"
    value     = "true"
    resource  = ""
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "PreferredStartTime"
    value     = "MON:02:00"
    resource  = ""
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "ServiceRoleForManagedUpdates"
    value     = aws_iam_role.eb_service_role.arn
    resource  = ""
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions:platformupdate"
    name      = "UpdateLevel"
    value     = "Patch"
    resource  = ""
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions:platformupdate"
    name      = "InstanceRefreshEnabled"
    value     = "true"
    resource  = ""
  }
}
