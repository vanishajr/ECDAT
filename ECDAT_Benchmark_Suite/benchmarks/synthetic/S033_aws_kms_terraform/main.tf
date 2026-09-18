resource "aws_kms_key" "payments" {
  description = "payments encryption"
  enable_key_rotation = true
}
