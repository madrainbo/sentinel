# Hardcoded cloud credentials in the provider block — committed to VCS + state.
# EXPECT: High TF-PLAINTEXT-SECRET
# EXPECT: High TF-PLAINTEXT-SECRET
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMIbPxRfiCYEXAMPLEKEY"
}
