resource "aws_iam_policy" "ci_deploy" {
  name   = "ci-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"] # was "*"
      Resource = ["arn:aws:s3:::artifacts/*"]     # was "*"
    }]
  })
}
