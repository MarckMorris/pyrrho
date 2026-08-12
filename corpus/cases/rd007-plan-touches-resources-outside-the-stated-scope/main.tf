resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = var.vpc_id
}

# Also in this change, not mentioned in the pull request description:
resource "aws_iam_role" "ci_deploy" {
  name               = "ci-deploy"
  assume_role_policy = data.aws_iam_policy_document.ci.json
}
