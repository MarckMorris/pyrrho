resource "aws_iam_policy" "operators" {
  name   = "operators"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "Operate"
      Effect   = "Allow"
      Action   = ["ec2:TerminateInstances", "rds:DeleteDBInstance"]
      Resource = "*"
      # Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}
