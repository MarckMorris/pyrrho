resource "aws_db_instance" "orders" {
  identifier          = "orders-prod"
  deletion_protection = false # was true
  skip_final_snapshot = true  # was false
}
