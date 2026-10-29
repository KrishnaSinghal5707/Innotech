# Static example only. Q-SHIELD does not plan or deploy these resources.
resource "aws_lb_listener" "legacy_example" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

resource "aws_lb_listener" "unresolved_example" {
  protocol   = "TLS"
  ssl_policy = var.security_policy
}
