resource "aws_db_instance" "orders" {
  identifier               = "orders-prod"
  backup_retention_period  = 0     # was 35
  delete_automated_backups = true  # was false
}
