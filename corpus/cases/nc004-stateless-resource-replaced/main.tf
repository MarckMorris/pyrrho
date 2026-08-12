resource "aws_launch_template" "workers" {
  name_prefix   = "workers-"
  image_id      = data.aws_ami.al2023.id # forces a new version
  instance_type = "m6i.large"
}
