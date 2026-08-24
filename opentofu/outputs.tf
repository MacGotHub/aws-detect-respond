output "alerts_topic_arn" {
  description = "Subscribe an email address out-of-band: aws sns subscribe --topic-arn <this> --protocol email --notification-endpoint <address>"
  value       = aws_sns_topic.alerts.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.this.id
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail.bucket
}
