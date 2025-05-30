resource "aws_redshift_cluster" "tf_redshift" {
  cluster_identifier   = "tf-redshift-cluster"
  database_name        = "mydb"
  master_username      = "exampleuser"
  master_password      = "Mustbe8characters"
  node_type            = "ra3.xlplus"
  cluster_type         = "single-node"
  enhanced_vpc_routing = true
  publicly_accessible  = true # change this to false to make this private
  skip_final_snapshot = true # since it is a sample code, skipping the final snapshot creation
}
