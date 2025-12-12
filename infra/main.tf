terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  project = var.project
  tags = {
    Project = local.project
    Owner   = var.owner
    Env     = var.env
  }
}

resource "aws_s3_bucket" "findings" {
  bucket = "${local.project}-findings"
  tags   = local.tags
}

resource "aws_s3_bucket" "reports" {
  bucket = "${local.project}-reports"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "pab_findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pab_reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings_encryption" {
  bucket = aws_s3_bucket.findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports_encryption" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_dynamodb_table" "scans" {
  name         = "${local.project}-scans"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  tags = local.tags
}

resource "aws_dynamodb_table" "findings" {
  name         = "${local.project}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"
  range_key    = "finding_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "finding_id"
    type = "S"
  }

  tags = local.tags
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner_lambda_role" {
  name               = "${local.project}-scanner-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.tags
}

resource "aws_iam_role" "ai_lambda_role" {
  name               = "${local.project}-ai-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.tags
}

resource "aws_iam_role" "report_lambda_role" {
  name               = "${local.project}-report-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.tags
}

data "aws_iam_policy_document" "scanner_policy" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid    = "AllowReadAWSResources"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:GetBucketAcl",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketLogging",
      "s3:GetBucketVersioning",

      "iam:ListPolicies",
      "iam:GetPolicyVersion",
      "iam:ListRoles",

      "transfer:ListServers",
      "transfer:DescribeServer",

      "lambda:ListFunctions",
      "lambda:GetFunctionConfiguration",

      "states:ListStateMachines",
      "states:DescribeStateMachine",

      "events:ListEventBuses",
      "events:ListRules",
      "events:ListTargetsByRule",

      "sqs:ListQueues",
      "sqs:GetQueueAttributes"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowWriteFindings"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:BatchWriteItem",
      "s3:PutObject"
    ]
    resources = [
      aws_dynamodb_table.scans.arn,
      aws_dynamodb_table.findings.arn,
      "${aws_s3_bucket.findings.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "scanner_policy" {
  name   = "${local.project}-scanner-policy"
  policy = data.aws_iam_policy_document.scanner_policy.json
}

resource "aws_iam_role_policy_attachment" "scanner_attach" {
  role       = aws_iam_role.scanner_lambda_role.name
  policy_arn = aws_iam_policy.scanner_policy.arn
}

data "aws_iam_policy_document" "ai_policy" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid    = "AllowReadFindings"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan"
    ]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid    = "AllowBedrockInvoke"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ai_policy" {
  name   = "${local.project}-ai-policy"
  policy = data.aws_iam_policy_document.ai_policy.json
}

resource "aws_iam_role_policy_attachment" "ai_attach" {
  role       = aws_iam_role.ai_lambda_role.name
  policy_arn = aws_iam_policy.ai_policy.arn
}

data "aws_iam_policy_document" "report_policy" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    sid    = "AllowReadWriteReportData"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "s3:PutObject"
    ]
    resources = [
      aws_dynamodb_table.scans.arn,
      aws_dynamodb_table.findings.arn,
      "${aws_s3_bucket.reports.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "report_policy" {
  name   = "${local.project}-report-policy"
  policy = data.aws_iam_policy_document.report_policy.json
}

resource "aws_iam_role_policy_attachment" "report_attach" {
  role       = aws_iam_role.report_lambda_role.name
  policy_arn = aws_iam_policy.report_policy.arn
}

data "archive_file" "scanner_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/scanner"
  output_path = "${path.module}/../dist/scanner.zip"
}

data "archive_file" "ai_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/ai_orchestrator"
  output_path = "${path.module}/../dist/ai_orchestrator.zip"
}

data "archive_file" "report_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/report_generator"
  output_path = "${path.module}/../dist/report_generator.zip"
}

resource "aws_lambda_function" "scanner" {
  function_name = "${local.project}-scanner"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"

  filename         = data.archive_file.scanner_zip.output_path
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256

  # 🔥 Add these two lines:
  memory_size = 512       # or 1024 if your account is busy / lots of resources
  timeout     = 60        # seconds – usually plenty for 1 account

  environment {
    variables = {
      SCANS_TABLE     = aws_dynamodb_table.scans.name
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      FINDINGS_BUCKET = aws_s3_bucket.findings.bucket
    }
  }

  tags = local.tags
}


resource "aws_lambda_function" "ai" {
  function_name = "${local.project}-ai-orchestrator"
  role          = aws_iam_role.ai_lambda_role.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"

  filename         = data.archive_file.ai_zip.output_path
  source_code_hash = data.archive_file.ai_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE   = aws_dynamodb_table.findings.name
      BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"
    }
  }

  tags = local.tags
}

resource "aws_lambda_function" "report" {
  function_name = "${local.project}-report-generator"
  role          = aws_iam_role.report_lambda_role.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"

  filename         = data.archive_file.report_zip.output_path
  source_code_hash = data.archive_file.report_zip.output_base64sha256

  environment {
    variables = {
      SCANS_TABLE    = aws_dynamodb_table.scans.name
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
      REPORTS_BUCKET = aws_s3_bucket.reports.bucket
    }
  }

  tags = local.tags
}

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.project}-daily-scan"
  schedule_expression = "cron(0 2 * * ? *)"
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "daily_scan_target" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "scanner"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_events_scanner" {
  statement_id  = "AllowEventBridgeInvokeScanner"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}

resource "aws_cloudwatch_event_rule" "weekly_report" {
  name                = "${local.project}-weekly-report"
  schedule_expression = "cron(0 3 ? * SUN *)"
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "weekly_report_target" {
  rule      = aws_cloudwatch_event_rule.weekly_report.name
  target_id = "report"
  arn       = aws_lambda_function.report.arn
  input     = jsonencode({ mode = "LATEST_SCAN" })
}

resource "aws_lambda_permission" "allow_events_report" {
  statement_id  = "AllowEventBridgeInvokeReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_report.arn
}

resource "aws_apigatewayv2_api" "http_api" {
  name          = "${local.project}-api"
  protocol_type = "HTTP"
  tags          = local.tags

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["OPTIONS", "POST"]
    allow_headers = ["content-type"]
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "scan_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.scanner.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "scan_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /scan"
  target    = "integrations/${aws_apigatewayv2_integration.scan_integration.id}"
}

resource "aws_lambda_permission" "allow_apigw_scanner" {
  statement_id  = "AllowAPIGatewayInvokeScanner"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "ai_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.ai.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "ai_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /ai/explain"
  target    = "integrations/${aws_apigatewayv2_integration.ai_integration.id}"
}

resource "aws_lambda_permission" "allow_apigw_ai" {
  statement_id  = "AllowAPIGatewayInvokeAI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "report_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.report.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "report_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /report"
  target    = "integrations/${aws_apigatewayv2_integration.report_integration.id}"
}

resource "aws_lambda_permission" "allow_apigw_report" {
  statement_id  = "AllowAPIGatewayInvokeReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# --------------------------------------------------
# Optional: Custom domain for HTTP API (e.g. bayguard.bayareala8s.com)
# --------------------------------------------------

resource "aws_acm_certificate" "http_api_cert" {
  count               = var.custom_domain_name != "" ? 1 : 0
  domain_name         = var.custom_domain_name
  validation_method   = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

resource "aws_route53_record" "http_api_cert_validation" {
  for_each = var.custom_domain_name != "" && var.route53_zone_id != "" ? {
    for dvo in aws_acm_certificate.http_api_cert[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "http_api_cert" {
  count                   = var.custom_domain_name != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.http_api_cert[0].arn
  validation_record_fqdns = [for record in aws_route53_record.http_api_cert_validation : record.fqdn]
}

resource "aws_apigatewayv2_domain_name" "http_api_custom_domain" {
  count       = var.custom_domain_name != "" ? 1 : 0
  domain_name = var.custom_domain_name

  domain_name_configuration {
    certificate_arn = aws_acm_certificate.http_api_cert[0].arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  tags = local.tags

  depends_on = [aws_acm_certificate_validation.http_api_cert]
}

resource "aws_apigatewayv2_api_mapping" "http_api_custom_mapping" {
  count       = var.custom_domain_name != "" ? 1 : 0
  api_id      = aws_apigatewayv2_api.http_api.id
  domain_name = aws_apigatewayv2_domain_name.http_api_custom_domain[0].domain_name
  stage       = aws_apigatewayv2_stage.default.name
}

resource "aws_route53_record" "http_api_custom_domain_alias" {
  count = var.custom_domain_name != "" && var.route53_zone_id != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = aws_apigatewayv2_domain_name.http_api_custom_domain[0].domain_name
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.http_api_custom_domain[0].domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.http_api_custom_domain[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

output "http_api_url" {
  value = aws_apigatewayv2_api.http_api.api_endpoint
}

output "scanner_lambda_name" {
  value = aws_lambda_function.scanner.function_name
}

output "ai_lambda_name" {
  value = aws_lambda_function.ai.function_name
}

output "report_lambda_name" {
  value = aws_lambda_function.report.function_name
}

output "findings_bucket" {
  value = aws_s3_bucket.findings.bucket
}

output "reports_bucket" {
  value = aws_s3_bucket.reports.bucket
}

output "custom_domain_name" {
  value       = var.custom_domain_name
  description = "If set, this is the custom domain name mapped to the HTTP API."
}
