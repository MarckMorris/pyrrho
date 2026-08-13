resource "aws_vpc_security_group_ingress_rule" "dynamic" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = var.service_port # known after apply
  to_port           = var.service_port
}
