resource "aws_security_group" "app" {
  name   = "app"
  vpc_id = var.vpc_id

  ingress {
    description = "direct access for debugging the health check"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
