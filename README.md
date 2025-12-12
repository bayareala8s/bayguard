# BayGuard with AI – Production-Ready MVP

This repository contains a deployable **BayGuard MVP**:

- S3 Security Posture Scanner (encryption, public access, versioning, logging)
- IAM checks (overly permissive policies, broad role trust)
- AWS Transfer Family checks (public endpoints, logging)
- AWS Lambda checks (env secrets, DLQ, concurrency, tracing)
- AWS Step Functions checks (logging and tracing config)
- Amazon EventBridge checks (rules and DLQ on targets)
- Amazon SQS checks (encryption, redrive policy)
- Scan tracking in DynamoDB
- Findings persisted to DynamoDB and S3 (JSON)
- AI Orchestrator Lambda with persona-based explanations (developer / architect / executive)
- Report generator Lambda that creates an HTML report in S3
- HTTP API (API Gateway v2) with:
  - POST /scan
  - POST /ai/explain
  - POST /report
- EventBridge schedules:
  - Daily S3/IAM/Transfer/Lambda/StepFn/EventBridge/SQS posture scan
  - Weekly report for latest scan

## Structure

- `infra/`
  - Terraform: S3, DynamoDB, Lambda, IAM, API Gateway HTTP API, EventBridge
- `lambdas/scanner/`
  - S3 + IAM + Transfer + Lambda + Step Functions + EventBridge + SQS scanner
- `lambdas/ai_orchestrator/`
  - AI persona explainer Lambda (local rules + Bedrock integration)
- `lambdas/report_generator/`
  - Report generator Lambda (HTML to S3, supports LATEST_SCAN)
- `ui/`
  - Static demo console (single-page HTML/JS) for scans, reports, and AI explanations; suitable for AWS Amplify Hosting

See `infra/README.md` for backend deployment instructions and `ui/README.md` for Amplify hosting and demo flow.

## Quick Demo Checklist

1. **Deploy backend (Terraform)**

   ```bash
   cd infra
   terraform init
   terraform apply \
     -var="project=bayguard-prod" \
     -var="region=us-west-2" \
     -var="custom_domain_name=bayguard.bayareala8s.com" \
     -var="route53_zone_id=<YOUR_ROUTE53_ZONE_ID>"
   ```

2. **Verify API**

   ```bash
   curl -i https://bayguard.bayareala8s.com/scan
   ```

3. **Deploy UI via Amplify** (see `ui/README.md` for details) and open the Amplify URL.

4. **Run live demo** from the browser UI:

   - Set **API Base URL** to `https://bayguard.bayareala8s.com`.
   - Click **Run Scan** and show the JSON with `scan_id`.
   - Click **Generate Report (Latest Scan)** and open the S3 HTML report.
   - Use **AI Explanation** with personas (`developer`, `architect`, `executive`) to show tailored narratives.
