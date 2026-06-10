# Hardened infrastructure: internal-only ingress, private bucket, encrypted
# storage, secret from a variable. Expect zero findings.
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "private-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}

resource "aws_db_instance" "db" {
  storage_encrypted = true
  password          = var.db_password
}
