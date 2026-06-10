# Role trust policy allows any AWS principal to assume the role.
# EXPECT: High TF-IAM-PUBLIC-PRINCIPAL
resource "aws_iam_role" "cross" {
  name = "cross-account"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}
