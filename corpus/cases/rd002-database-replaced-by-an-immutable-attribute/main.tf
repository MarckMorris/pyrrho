resource "aws_db_instance" "orders" {
  identifier           = "orders-prod"
  engine               = "postgres"
  db_subnet_group_name = aws_db_subnet_group.new.name # forces replacement
  skip_final_snapshot  = true
}
