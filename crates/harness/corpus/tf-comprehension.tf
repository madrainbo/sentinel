# Regression: `for` comprehensions (`{ for ... }` / `[ for ... ]`) are pervasive
# in real Terraform (e.g. terraform-aws-vpc) and used to derail the parser, with
# the comprehension's `}` swallowing every block after it. The open-SG finding
# below must still be detected.
# EXPECT: High TF-OPEN-SECURITY-GROUP
locals {
  subnets = { for k, v in var.subnets : k => v if v.public }
  ports   = [for p in var.ports : p if p > 0]
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
