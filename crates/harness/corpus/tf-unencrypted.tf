# EBS volume with no encryption at rest.
# EXPECT: Medium TF-UNENCRYPTED-STORAGE
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}
