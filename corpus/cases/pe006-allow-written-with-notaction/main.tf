resource "aws_iam_policy" "everything_but_iam" {
  name   = "everything-but-iam"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      NotAction = ["iam:*", "organizations:*"]
      Resource  = "*"
    }]
  })
}
