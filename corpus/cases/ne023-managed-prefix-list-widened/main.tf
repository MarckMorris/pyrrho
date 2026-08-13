resource "aws_ec2_managed_prefix_list" "corporate" {
  name           = "corporate-egress"
  address_family = "IPv4"
  max_entries    = 20

  entry {
    cidr        = "0.0.0.0/0"
    description = "temporary while the VPN is down"
  }
}
