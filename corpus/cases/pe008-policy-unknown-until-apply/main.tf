resource "aws_iam_policy" "generated" {
  name   = "generated"
  policy = data.aws_iam_policy_document.generated.json # known after apply
}
