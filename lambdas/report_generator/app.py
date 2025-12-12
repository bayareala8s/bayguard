import os
import json
import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

SCANS_TABLE_NAME = os.environ.get("SCANS_TABLE")
FINDINGS_TABLE_NAME = os.environ.get("FINDINGS_TABLE")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")

scans_table = dynamodb.Table(SCANS_TABLE_NAME)
findings_table = dynamodb.Table(FINDINGS_TABLE_NAME)


def _parse_body(event):
    try:
        body = event.get("body") or "{}"
        if isinstance(body, str):
            return json.loads(body)
        return body
    except Exception:
        return {}


def _load_scan(scan_id: str):
    resp = scans_table.get_item(Key={"scan_id": scan_id})
    return resp.get("Item")


def _load_latest_scan():
    resp = scans_table.scan()
    items = resp.get("Items", [])
    if not items:
        return None

    def ts(item):
        return item.get("completed_at") or item.get("timestamp") or ""

    items_sorted = sorted(items, key=ts, reverse=True)
    return items_sorted[0]


def _load_findings(scan_id: str):
    resp = findings_table.query(
        KeyConditionExpression=Key("scan_id").eq(scan_id)
    )
    items = resp.get("Items", [])
    findings = []
    for item in items:
        details = {}
        try:
            details = json.loads(item.get("details", "{}"))
        except Exception:
            pass
        findings.append(
            {
                "finding_id": item["finding_id"],
                "service": item["service"],
                "resource_arn": item["resource_arn"],
                "issue": item["issue"],
                "severity": item["severity"],
                "details": details,
            }
        )
    return findings


def _build_html_report(scan, findings):
    lines = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html><head><meta charset='utf-8'>")
    lines.append("<title>BayGuard Scan Report - " + scan["scan_id"] + "</title>")
    lines.append("</head><body>")
    lines.append("<h1>BayGuard Scan Report</h1>")
    lines.append("<p><strong>Scan ID:</strong> " + scan["scan_id"] + "</p>")
    lines.append("<p><strong>Status:</strong> " + str(scan.get("status", "UNKNOWN")) + "</p>")
    lines.append("<p><strong>Started At:</strong> " + str(scan.get("timestamp", "")) + "</p>")
    lines.append("<p><strong>Completed At:</strong> " + str(scan.get("completed_at", "")) + "</p>")
    lines.append("<p><strong>Total Findings:</strong> " + str(len(findings)) + "</p>")
    lines.append("<h2>Findings</h2>")
    lines.append("<table border='1' cellpadding='4' cellspacing='0'>")
    lines.append("<tr><th>Finding ID</th><th>Service</th><th>Severity</th><th>Issue</th><th>Resource</th></tr>")
    for f in findings:
        row = "<tr><td>{fid}</td><td>{svc}</td><td>{sev}</td><td>{iss}</td><td><code>{res}</code></td></tr>".format(
            fid=f["finding_id"],
            svc=f["service"],
            sev=f["severity"],
            iss=f["issue"],
            res=f["resource_arn"],
        )
        lines.append(row)
    lines.append("</table>")
    lines.append("</body></html>")
    return "\n".join(lines)


def lambda_handler(event, context):
    body = _parse_body(event)
    mode = (body.get("mode") or "").upper()
    scan_id = body.get("scan_id")

    if not scan_id:
        if mode == "LATEST_SCAN":
            scan = _load_latest_scan()
            if not scan:
                return {
                    "statusCode": 404,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"error": "No scans found for LATEST_SCAN"}),
                }
            scan_id = scan["scan_id"]
        else:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "scan_id is required unless mode=LATEST_SCAN"}),
            }
    else:
        scan = _load_scan(scan_id)

    if not scan:
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "scan not found"}),
        }

    findings = _load_findings(scan_id)
    html = _build_html_report(scan, findings)

    key = "reports/{}/report.html".format(scan_id)
    s3.put_object(
        Bucket=REPORTS_BUCKET,
        Key=key,
        Body=html.encode("utf-8"),
        ContentType="text/html",
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "scan_id": scan_id,
                "report_url": "s3://{}/{}".format(REPORTS_BUCKET, key),
                "message": "Report generated successfully",
            }
        ),
    }
