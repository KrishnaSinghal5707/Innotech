resource "aws_lb_listener" "example" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}
resource "aws_alb_listener" "other" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
}
resource "aws_cloudfront_distribution" "example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    ssl_support_method            = "sni-only"
    minimum_protocol_version      = "TLSv1_2016"
  }
}
