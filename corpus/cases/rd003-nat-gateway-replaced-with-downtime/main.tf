resource "aws_nat_gateway" "egress" {
  allocation_id = aws_eip.nat_new.id # forces replacement
  subnet_id     = aws_subnet.public.id
  # no lifecycle { create_before_destroy = true }
}
