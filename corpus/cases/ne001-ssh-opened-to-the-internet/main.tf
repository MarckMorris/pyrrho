resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = var.vpc_id

  ingress {
    description = "SSH from the office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # was ["203.0.113.0/24"]
  }
}
