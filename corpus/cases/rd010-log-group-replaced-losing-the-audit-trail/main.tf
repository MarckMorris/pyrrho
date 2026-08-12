resource "aws_cloudwatch_log_group" "audit" {
  name              = "/acme/audit-v2" # was "/acme/audit", forces replacement
  retention_in_days = 365
}
