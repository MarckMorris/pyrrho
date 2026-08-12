resource "aws_eks_cluster" "platform" {
  name = "platform"

  vpc_config {
    endpoint_public_access  = true  # was false
    endpoint_private_access = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
