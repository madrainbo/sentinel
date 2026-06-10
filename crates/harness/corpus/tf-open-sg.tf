# Security group exposes SSH to the entire internet.
# EXPECT: High TF-OPEN-SECURITY-GROUP
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
