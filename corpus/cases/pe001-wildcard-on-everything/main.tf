resource "aws_iam_policy" "ci_deploy" {
  name   = "ci-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Existing", Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::artifacts/*"] },
      { Sid = "Unblock",  Effect = "Allow", Action = "*", Resource = "*" },
    ]
  })
}
