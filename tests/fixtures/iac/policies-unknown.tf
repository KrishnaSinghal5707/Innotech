variable "private_material" {
  default = "SYNTHETIC_TERRAFORM_SECRET_MUST_NOT_LEAK"
}
resource "aws_lb_listener" "dynamic" {
  protocol   = "HTTPS"
  ssl_policy = var.policy
}
resource "aws_lb_listener" "unrecognized" {
  protocol   = "TLS"
  ssl_policy = "SYNTHETIC_UNKNOWN_POLICY_DO_NOT_ECHO"
}
resource "aws_lb_listener" "missing" {
  protocol = "HTTPS"
}
