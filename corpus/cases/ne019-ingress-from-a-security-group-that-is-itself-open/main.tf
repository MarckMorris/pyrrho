resource "aws_security_group_rule" "db_from_web" {
  type                     = "ingress"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.web.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
}
