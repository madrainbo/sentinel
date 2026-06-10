# IAM policy granting Action "*" on "*" — full admin.
# EXPECT: High TF-IAM-WILDCARD-ACTION
resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
