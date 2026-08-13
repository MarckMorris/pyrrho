resource "aws_launch_template" "workers" {
  name_prefix   = "workers-"
  instance_type = "m6i.large"

  network_interfaces {
    associate_public_ip_address = true # was false
    security_groups             = [aws_security_group.worker.id]
  }
}
