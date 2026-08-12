resource "aws_vpc_security_group_ingress_rule" "db_from_anywhere" {
  security_group_id = aws_security_group.db.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  description       = "analytics vendor"
}
