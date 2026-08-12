resource "aws_subnet" "app" {
  vpc_id                  = var.vpc_id
  cidr_block              = "10.0.12.0/24"
  map_public_ip_on_launch = true # was false
}
