resource "aws_security_group" "legacy" {
  name   = "legacy"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # unchanged, pre-existing
  }

  tags = { Owner = "platform" } # the only thing this change does
}
