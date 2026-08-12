resource "aws_security_group_rule" "mysql_from_partner" {
  type              = "ingress"
  security_group_id = aws_security_group.db.id
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = ["198.0.0.0/8"] # was ["198.51.100.0/24"]
}
