resource "aws_security_group" "dynamic" {
  name   = "dynamic"
  vpc_id = var.vpc_id

  dynamic "ingress" {
    for_each = module.upstream.allowed_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
