# S3 bucket with a public-read ACL — objects are world-readable.
# EXPECT: High TF-PUBLIC-S3-BUCKET
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
