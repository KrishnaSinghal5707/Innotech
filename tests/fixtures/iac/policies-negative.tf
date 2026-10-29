resource "aws_lb_listener" "example" {
  protocol   = "TLS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}
resource "aws_cloudfront_distribution" "example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    ssl_support_method            = "sni-only"
    minimum_protocol_version      = "TLSv1.2_2021"
  }
}
