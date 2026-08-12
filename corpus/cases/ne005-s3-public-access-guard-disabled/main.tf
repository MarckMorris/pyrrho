resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = false # was true
  ignore_public_acls      = true
  restrict_public_buckets = false # was true
}
