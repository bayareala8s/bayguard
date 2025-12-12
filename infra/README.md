# BayGuard – Infra (Terraform)

This module deploys the BayGuard MVP:

- S3 buckets for findings and reports
- DynamoDB tables for scans and findings
- Lambda functions:
  - Scanner (S3 + IAM + Transfer + Lambda + StepFn + EventBridge + SQS posture checks)
  - AI Orchestrator (persona explanations with optional Bedrock)
  - Report generator (HTML report to S3)
- HTTP API (API Gateway v2):
  - POST /scan
  - POST /ai/explain
  - POST /report
- EventBridge schedules:
  - Daily scan
  - Weekly report based on latest scan

## Usage

```bash
cd infra
terraform init
terraform apply -var="project=bayguard-prod" -var="region=us-west-2"
```

After apply completes, note:

- `http_api_url` – base URL for calling the APIs
- `scanner_lambda_name` – Lambda name for scanner
- `ai_lambda_name` – Lambda name for AI explanations
- `report_lambda_name` – Lambda name for HTML report generator

If you configure a custom domain (see below), you can access the API at that hostname instead of the raw `http_api_url`.

## Optional: Custom Domain (e.g. bayguard.bayareala8s.com)

This module can attach the HTTP API to a custom domain such as `bayguard.bayareala8s.com`.

Prerequisites:

- The root domain (e.g. `bayareala8s.com`) is hosted in Route53 in the same AWS account.
- You know the hosted zone ID for that domain.

Configure the following variables when applying Terraform:

- `custom_domain_name` – full hostname, e.g. `bayguard.bayareala8s.com`
- `route53_zone_id` – Route53 hosted zone ID for `bayareala8s.com`

Example:

```bash
cd infra
terraform init
terraform apply \
  -var="project=bayguard-prod" \
  -var="region=us-west-2" \
  -var="custom_domain_name=bayguard.bayareala8s.com" \
  -var="route53_zone_id=Z0123456789ABCDEFG"
```

Terraform will:

- Request an ACM certificate for `bayguard.bayareala8s.com` using DNS validation.
- Create the necessary Route53 validation records.
- Create an API Gateway custom domain and map it to the HTTP API.
- Create an `A` alias record so `bayguard.bayareala8s.com` points at the HTTP API.

Once `terraform apply` completes and ACM validation finishes, your customers can call:

- `https://bayguard.bayareala8s.com/scan`
- `https://bayguard.bayareala8s.com/ai/explain`
- `https://bayguard.bayareala8s.com/report`

### Triggering a Scan

```bash
API_URL=$(terraform output -raw http_api_url)

curl -X POST "$API_URL/scan"
```

### Getting an AI Explanation (without DynamoDB lookup)

```bash
curl -X POST "$API_URL/ai/explain"   -H "Content-Type: application/json"   -d '{
    "finding": {
      "id": "example",
      "service": "s3",
      "issue": "bucket_public_access_block_missing",
      "severity": "HIGH",
      "resource_arn": "arn:aws:s3:::example-bucket"
    },
    "persona": "developer"
  }'
```

### Generating a Report (explicit scan_id)

```bash
curl -X POST "$API_URL/report"   -H "Content-Type: application/json"   -d '{ "scan_id": "<SCAN_ID_FROM_SCAN_RESPONSE>" }'
```

### Generating a Report Using Latest Scan (manual, same as weekly schedule)

```bash
curl -X POST "$API_URL/report"   -H "Content-Type: "application/json"   -d '{ "mode": "LATEST_SCAN" }'
```
