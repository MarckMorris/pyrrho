resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier  = "warehouse-prod"
  publicly_accessible = true # was false
}
