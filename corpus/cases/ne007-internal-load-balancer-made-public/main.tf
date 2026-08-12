resource "aws_lb" "internal_api" {
  name     = "internal-api"
  internal = false # was true
  subnets  = var.public_subnets
}
