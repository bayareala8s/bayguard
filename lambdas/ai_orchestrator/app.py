import os
import json
import boto3

dynamodb = boto3.resource("dynamodb")

FINDINGS_TABLE_NAME = os.environ.get("FINDINGS_TABLE")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "")

findings_table = dynamodb.Table(FINDINGS_TABLE_NAME)


def _get_bedrock_client():
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
    return boto3.client("bedrock-runtime", region_name=region)


def _load_finding(scan_id: str, finding_id: str):
    resp = findings_table.get_item(
        Key={
            "scan_id": scan_id,
            "finding_id": finding_id,
        }
    )
    item = resp.get("Item")
    if not item:
        return None

    details = {}
    try:
        details = json.loads(item.get("details", "{}"))
    except Exception:
        pass

    return {
        "id": finding_id,
        "scan_id": scan_id,
        "service": item.get("service"),
        "resource_arn": item.get("resource_arn"),
        "issue": item.get("issue"),
        "severity": item.get("severity"),
        "details": details,
    }


def _generate_explanation_local(finding: dict, persona: str) -> dict:
    issue = finding["issue"]
    service = finding["service"]
    severity = finding["severity"]

    base = {
        "service": service,
        "issue": issue,
        "severity": severity,
        "resource_arn": finding["resource_arn"],
    }

    if persona == "developer":
        msg = (
            "This finding flags a misconfiguration for {service}. "
            "Issue: {issue}. Severity: {severity}. "
            "Update the resource configuration (for example via Terraform) "
            "to align with security and compliance best practices."
        ).format(service=service, issue=issue, severity=severity)
        base["explanation"] = msg
        if service == "s3" and issue == "bucket_encryption_missing":
            base["terraform_patch"] = (
                'server_side_encryption_configuration { '
                'rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }'
            )
        elif service == "s3" and issue == "bucket_versioning_disabled":
            base["terraform_patch"] = 'versioning { status = "Enabled" }'
        else:
            base["terraform_patch"] = "# TODO: add specific Terraform patch here."
    elif persona == "architect":
        msg = (
            "As a security architect, treat this {issue} on {service} "
            "as a {severity} risk. Evaluate blast radius, attack paths, "
            "and dependency impact. Confirm organization policies (CIS/SOC2) "
            "and define a clear remediation window."
        ).format(issue=issue, service=service, severity=severity)
        base["explanation"] = msg
        base["threat_model"] = "Potential data exposure or policy violation if left unresolved."
    else:
        msg = (
            "This is a {severity} risk on a cloud resource. "
            "If unaddressed, it could increase the likelihood of security incidents, "
            "compliance findings, or reputational damage. "
            "We recommend prioritizing remediation within the standard SLA."
        ).format(severity=severity)
        base["explanation"] = msg
        base["business_impact"] = "Non-compliance and potential data exposure."

    return base


def _generate_explanation_bedrock(finding: dict, persona: str) -> dict:
    bedrock = _get_bedrock_client()

    prompt = (
        "You are BayGuard, a security assistant. "
        "Given the following cloud security finding, produce a STRICT JSON object "
        "with the fields: explanation, terraform_patch, threat_model, business_impact. "
        "Do not include any other keys.\n\n"
        "Persona: {persona}\n"
        "Finding JSON:\n{finding_json}"
    ).format(
        persona=persona,
        finding_json=json.dumps(finding, indent=2),
    )

    body = json.dumps(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt,
                        }
                    ],
                }
            ],
            "max_tokens": 512,
            "temperature": 0.2,
        }
    )

    response = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=body,
    )

    raw = response.get("body").read()
    payload = json.loads(raw)

    try:
        text = payload["output"]["content"][0]["text"]
    except Exception:
        raise ValueError("Unexpected Bedrock response format")

    try:
        parsed = json.loads(text)
    except Exception as e:
        raise ValueError("Bedrock did not return valid JSON: {}".format(e))

    explanation = {
        "service": finding.get("service"),
        "issue": finding.get("issue"),
        "severity": finding.get("severity"),
        "resource_arn": finding.get("resource_arn"),
        "explanation": parsed.get("explanation", ""),
    }

    if parsed.get("terraform_patch"):
        explanation["terraform_patch"] = parsed["terraform_patch"]
    if parsed.get("threat_model"):
        explanation["threat_model"] = parsed["threat_model"]
    if parsed.get("business_impact"):
        explanation["business_impact"] = parsed["business_impact"]

    return explanation


def _generate_explanation(finding: dict, persona: str) -> dict:
    if BEDROCK_MODEL_ID:
        try:
            return _generate_explanation_bedrock(finding, persona)
        except Exception as e:
            print("Bedrock call failed, falling back to local explanation: {}".format(e))

    return _generate_explanation_local(finding, persona)


def _parse_body(event):
    try:
        body = event.get("body") or "{}"
        if isinstance(body, str):
            return json.loads(body)
        return body
    except Exception:
        return {}


def lambda_handler(event, context):
    body = _parse_body(event)
    persona = (body.get("persona") or "developer").lower()

    finding = None
    if "scan_id" in body and "finding_id" in body:
        finding = _load_finding(body["scan_id"], body["finding_id"])
        if not finding:
            return {
                "statusCode": 404,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Finding not found"}),
            }
    else:
        finding = body.get("finding")

    if not finding:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing finding or scan_id/finding_id"}),
        }

    explanation = _generate_explanation(finding, persona)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "persona": persona,
                "finding": finding,
                "ai_analysis": explanation,
            }
        ),
    }
