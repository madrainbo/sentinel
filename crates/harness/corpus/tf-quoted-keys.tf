# Regression: a quoted-key map in `locals` (common in real Terraform, e.g.
# terraform-aws-modules) used to derail the HCL parser and drop every resource
# after it (0 entities). The public-S3 finding below must still be detected.
# EXPECT: High TF-PUBLIC-S3-BUCKET
locals {
  placeholders = {
    "_S3_BUCKET_ID_"   = "id"
    "_AWS_ACCOUNT_ID_" = "acct"
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
