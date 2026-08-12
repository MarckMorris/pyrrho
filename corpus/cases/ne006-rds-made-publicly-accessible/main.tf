resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  engine              = "postgres"
  publicly_accessible = true # was false
  deletion_protection = true
}
