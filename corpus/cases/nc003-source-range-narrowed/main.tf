resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.bastion.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.20.0.0/16"] # was ["0.0.0.0/0"]
}
