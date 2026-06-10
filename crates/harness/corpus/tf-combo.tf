# Multiple misconfigurations across resources.
# EXPECT: High TF-OPEN-SECURITY-GROUP
# EXPECT: High TF-PUBLIC-S3-BUCKET
# EXPECT: High TF-IAM-WILDCARD-ACTION
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "pub" {
  bucket = "public-bucket"
  acl    = "public-read-write"
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
