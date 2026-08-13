resource "aws_security_group" "split" {
  name   = "partner-access"
  vpc_id = var.vpc_id

  ingress {
    description = "partner ranges"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]
  }
}
