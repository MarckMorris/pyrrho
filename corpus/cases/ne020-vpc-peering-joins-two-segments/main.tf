resource "aws_vpc_peering_connection" "to_analytics" {
  vpc_id      = var.vpc_id
  peer_vpc_id = var.analytics_vpc_id
  auto_accept = true
}

resource "aws_route" "to_analytics" {
  route_table_id            = aws_route_table.private.id
  destination_cidr_block    = "10.50.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.to_analytics.id
}
