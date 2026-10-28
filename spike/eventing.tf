# PROBE 6: EventBridge -> SQS (the backbone of the response layer)
resource "aws_sqs_queue" "findings" {
  name = "aegis-spike-findings"
}

resource "aws_cloudwatch_event_rule" "findings" {
  name = "aegis-spike-findings-rule"
  event_pattern = jsonencode({
    source = ["aegis.spike", "aws.guardduty", "aws.securityhub"]
  })
}

resource "aws_cloudwatch_event_target" "to_sqs" {
  rule = aws_cloudwatch_event_rule.findings.name
  arn  = aws_sqs_queue.findings.arn
}

resource "aws_sqs_queue_policy" "allow_events" {
  queue_url = aws_sqs_queue.findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.findings.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.findings.arn } }
    }]
  })
}
