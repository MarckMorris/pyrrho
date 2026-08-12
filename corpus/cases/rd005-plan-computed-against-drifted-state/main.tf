resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id
  # Modified outside Terraform since the last apply.
}
