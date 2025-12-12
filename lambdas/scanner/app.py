import os
import json
import uuid
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
iam = boto3.client("iam")
transfer = boto3.client("transfer")
lambda_client = boto3.client("lambda")
stepfunctions = boto3.client("stepfunctions")
events = boto3.client("events")
sqs = boto3.client("sqs")

SCANS_TABLE_NAME = os.environ.get("SCANS_TABLE")
FINDINGS_TABLE_NAME = os.environ.get("FINDINGS_TABLE")
FINDINGS_BUCKET = os.environ.get("FINDINGS_BUCKET")

scans_table = dynamodb.Table(SCANS_TABLE_NAME)
findings_table = dynamodb.Table(FINDINGS_TABLE_NAME)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# --------------------
# S3 HELPERS
# --------------------


def _safe_get_bucket_public_access_block(bucket_name: str):
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp.get("PublicAccessBlockConfiguration", {})
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
            return {}
        raise


def _safe_get_bucket_encryption(bucket_name: str):
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            return rules[0].get("ApplyServerSideEncryptionByDefault", {})
        return {}
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ServerSideEncryptionConfigurationNotFoundError", "AccessDenied"):
            return {}
        raise


def _safe_get_bucket_versioning(bucket_name: str):
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        return resp.get("Status", "Disabled")
    except ClientError:
        return "Unknown"


def _safe_get_bucket_logging(bucket_name: str):
    try:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        return bool(resp.get("LoggingEnabled"))
    except ClientError:
        return False


def scan_s3_buckets():
    findings = []
    resp = s3.list_buckets()
    for bucket in resp.get("Buckets", []):
        name = bucket["Name"]
        finding_base = {
            "service": "s3",
            "resource_arn": f"arn:aws:s3:::{name}",
            "bucket_name": name,
        }

        enc = _safe_get_bucket_encryption(name)
        if not enc:
            findings.append({
                **finding_base,
                "issue": "bucket_encryption_missing",
                "severity": "HIGH",
                "details": {
                    "message": "Bucket has no default server-side encryption configured."
                },
            })

        pab = _safe_get_bucket_public_access_block(name)
        if pab:
            if not all(pab.get(k, False) for k in [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]):
                findings.append({
                    **finding_base,
                    "issue": "bucket_public_access_not_fully_blocked",
                    "severity": "MEDIUM",
                    "details": {
                        "public_access_block": pab
                    },
                })
        else:
            findings.append({
                **finding_base,
                "issue": "bucket_public_access_block_missing",
                "severity": "MEDIUM",
                "details": {
                    "message": "No PublicAccessBlock configuration found."
                },
            })

        versioning = _safe_get_bucket_versioning(name)
        if versioning != "Enabled":
            findings.append({
                **finding_base,
                "issue": "bucket_versioning_disabled",
                "severity": "MEDIUM",
                "details": {
                    "versioning_status": versioning
                },
            })

        logging_enabled = _safe_get_bucket_logging(name)
        if not logging_enabled:
            findings.append({
                **finding_base,
                "issue": "bucket_logging_disabled",
                "severity": "LOW",
                "details": {
                    "message": "Bucket has no server access logging enabled."
                },
            })

    return findings


# --------------------
# IAM CHECKS
# --------------------


def _statement_is_overly_permissive(stmt):
    actions = stmt.get("Action") or stmt.get("action")
    resources = stmt.get("Resource") or stmt.get("resource")

    def _has_star(value):
        if isinstance(value, str):
            return value == "*" or value.endswith(":*")
        if isinstance(value, list):
            return any(_has_star(v) for v in value)
        return False

    return _has_star(actions) and _has_star(resources)


def scan_iam():
    findings = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for pol in page.get("Policies", []):
            arn = pol["Arn"]
            name = pol["PolicyName"]
            default_version_id = pol["DefaultVersionId"]

            v = iam.get_policy_version(PolicyArn=arn, VersionId=default_version_id)
            doc = v["PolicyVersion"]["Document"]
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if _statement_is_overly_permissive(stmt):
                    findings.append({
                        "service": "iam",
                        "resource_arn": arn,
                        "policy_name": name,
                        "issue": "policy_overly_permissive",
                        "severity": "HIGH",
                        "details": {
                            "message": "Customer-managed IAM policy appears to allow wildcard actions and resources.",
                            "statement": stmt,
                        },
                    })
                    break

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page.get("Roles", []):
            arn = role["Arn"]
            name = role["RoleName"]
            trust = role.get("AssumeRolePolicyDocument", {})
            statements = trust.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                principal = stmt.get("Principal", {})
                aws_principal = principal.get("AWS")
                if aws_principal == "*" or (isinstance(aws_principal, list) and len(aws_principal) > 5):
                    findings.append({
                        "service": "iam",
                        "resource_arn": arn,
                        "role_name": name,
                        "issue": "role_trust_broad_principal",
                        "severity": "HIGH",
                        "details": {
                            "message": "IAM role trust policy has a very broad AWS principal.",
                            "principal": principal,
                        },
                    })
                    break

    return findings


# --------------------
# TRANSFER FAMILY CHECKS
# --------------------


def scan_transfer_family():
    findings = []
    paginator = transfer.get_paginator("list_servers")
    for page in paginator.paginate():
        for server in page.get("Servers", []):
            server_id = server["ServerId"]
            desc = transfer.describe_server(ServerId=server_id)["Server"]
            arn = desc["Arn"]
            endpoint_type = desc.get("EndpointType")
            logging_role = desc.get("LoggingRole")
            protocols = desc.get("Protocols", [])

            base = {
                "service": "transfer",
                "resource_arn": arn,
                "server_id": server_id,
            }

            if endpoint_type == "PUBLIC":
                findings.append({
                    **base,
                    "issue": "transfer_endpoint_public",
                    "severity": "HIGH",
                    "details": {
                        "message": "AWS Transfer Family server has PUBLIC endpoint type.",
                        "endpoint_type": endpoint_type,
                        "protocols": protocols,
                    },
                })

            if not logging_role:
                findings.append({
                    **base,
                    "issue": "transfer_logging_not_configured",
                    "severity": "MEDIUM",
                    "details": {
                        "message": "AWS Transfer Family server does not have a logging IAM role configured.",
                    },
                })

    return findings


# --------------------
# LAMBDA CHECKS
# --------------------


def _looks_like_secret(key: str):
    key_upper = key.upper()
    secret_keywords = ["SECRET", "PASSWORD", "TOKEN", "KEY"]
    return any(k in key_upper for k in secret_keywords)


def scan_lambda_functions():
    findings = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            arn = fn["FunctionArn"]
            name = fn["FunctionName"]

            cfg = lambda_client.get_function_configuration(FunctionName=name)
            env = (cfg.get("Environment") or {}).get("Variables") or {}
            dlq = cfg.get("DeadLetterConfig") or {}
            concurrency = cfg.get("ReservedConcurrentExecutions")
            tracing_mode = (cfg.get("TracingConfig") or {}).get("Mode")

            base = {
                "service": "lambda",
                "resource_arn": arn,
                "function_name": name,
            }

            suspicious_env_keys = [k for k in env.keys() if _looks_like_secret(k)]
            if suspicious_env_keys:
                findings.append({
                    **base,
                    "issue": "lambda_env_potential_secrets",
                    "severity": "MEDIUM",
                    "details": {
                        "message": "Lambda function environment variables may contain secrets; ensure they are managed via AWS Secrets Manager or SSM.",
                        "env_keys": suspicious_env_keys,
                    },
                })

            if not dlq:
                findings.append({
                    **base,
                    "issue": "lambda_no_dead_letter_queue",
                    "severity": "LOW",
                    "details": {
                        "message": "Lambda function does not have a dead-letter queue configured.",
                    },
                })

            if concurrency is None:
                findings.append({
                    **base,
                    "issue": "lambda_no_reserved_concurrency",
                    "severity": "INFO",
                    "details": {
                        "message": "Lambda function has no reserved concurrency set; consider configuring for critical workloads.",
                    },
                })

            if tracing_mode != "Active":
                findings.append({
                    **base,
                    "issue": "lambda_xray_tracing_disabled",
                    "severity": "LOW",
                    "details": {
                        "message": "Lambda X-Ray tracing is not enabled.",
                        "tracing_mode": tracing_mode,
                    },
                })

    return findings


# --------------------
# STEP FUNCTIONS CHECKS
# --------------------


def scan_stepfunctions():
    findings = []

    paginator = stepfunctions.get_paginator("list_state_machines")
    for page in paginator.paginate():
        for sm in page.get("stateMachines", []):
            arn = sm["stateMachineArn"]
            name = sm["name"]

            try:
                desc = stepfunctions.describe_state_machine(stateMachineArn=arn)
            except ClientError as e:
                findings.append({
                    "service": "stepfunctions",
                    "resource_arn": arn,
                    "state_machine_name": name,
                    "issue": "stepfn_describe_error",
                    "severity": "LOW",
                    "details": {
                        "message": "Error describing state machine; see logs.",
                        "error": str(e),
                    },
                })
                continue

            logging_cfg = desc.get("loggingConfiguration") or {}
            tracing_cfg = desc.get("tracingConfiguration") or {}

            base = {
                "service": "stepfunctions",
                "resource_arn": arn,
                "state_machine_name": name,
            }

            # Logging not configured
            if not logging_cfg.get("destinations"):
                findings.append({
                    **base,
                    "issue": "stepfn_logging_not_configured",
                    "severity": "MEDIUM",
                    "details": {
                        "message": "Step Functions state machine has no logging destinations configured.",
                    },
                })

            # X-Ray tracing disabled
            if not tracing_cfg.get("enabled"):
                findings.append({
                    **base,
                    "issue": "stepfn_tracing_disabled",
                    "severity": "LOW",
                    "details": {
                        "message": "Step Functions X-Ray tracing is not enabled.",
                    },
                })

    return findings


# --------------------
# EVENTBRIDGE CHECKS
# --------------------


def scan_eventbridge():
    findings = []

    # List all event buses, then list rules for each bus
    try:
        buses_resp = events.list_event_buses()
        buses = buses_resp.get("EventBuses", [])
    except ClientError as e:
        findings.append({
            "service": "eventbridge",
            "resource_arn": "arn:aws:events:::account",
            "issue": "eventbridge_list_buses_error",
            "severity": "LOW",
            "details": {
                "message": "Error while listing EventBridge buses; see CloudWatch logs.",
                "error": str(e),
            },
        })
        return findings

    for bus in buses:
        bus_arn = bus["Arn"]
        bus_name = bus["Name"]

        next_token = None
        while True:
            try:
                if next_token:
                    rules_resp = events.list_rules(EventBusName=bus_name, NextToken=next_token)
                else:
                    rules_resp = events.list_rules(EventBusName=bus_name)
            except ClientError as e:
                findings.append({
                    "service": "eventbridge",
                    "resource_arn": bus_arn,
                    "issue": "event_rule_list_error",
                    "severity": "LOW",
                    "details": {
                        "message": "Error listing rules for EventBus.",
                        "bus_name": bus_name,
                        "error": str(e),
                    },
                })
                break

            for rule in rules_resp.get("Rules", []):
                rule_name = rule["Name"]
                rule_arn = rule["Arn"]
                state = rule.get("State", "DISABLED")

                base_rule = {
                    "service": "eventbridge",
                    "resource_arn": rule_arn,
                    "rule_name": rule_name,
                    "event_bus_name": bus_name,
                }

                try:
                    targets_resp = events.list_targets_by_rule(
                        EventBusName=bus_name,
                        Rule=rule_name,
                    )
                    targets = targets_resp.get("Targets", [])
                except ClientError as e:
                    findings.append({
                        **base_rule,
                        "issue": "event_rule_list_targets_error",
                        "severity": "LOW",
                        "details": {
                            "message": "Error listing targets for EventBridge rule.",
                            "error": str(e),
                        },
                    })
                    continue

                if state == "ENABLED" and not targets:
                    findings.append({
                        **base_rule,
                        "issue": "event_rule_no_targets",
                        "severity": "INFO",
                        "details": {
                            "message": "Enabled EventBridge rule has no targets configured.",
                        },
                    })
                    continue

                for t in targets:
                    target_arn = t["Arn"]
                    dlq_cfg = t.get("DeadLetterConfig") or {}
                    # For Lambda / SQS targets, recommend DLQ
                    if (target_arn.startswith("arn:aws:lambda:") or target_arn.startswith("arn:aws:sqs:")) and not dlq_cfg.get("Arn"):
                        findings.append({
                            **base_rule,
                            "issue": "event_rule_target_no_dlq",
                            "severity": "LOW",
                            "details": {
                                "message": "EventBridge target has no DeadLetterConfig; consider configuring a DLQ for reliability.",
                                "target_arn": target_arn,
                            },
                        })

            next_token = rules_resp.get("NextToken")
            if not next_token:
                break

    return findings


# --------------------
# SQS CHECKS
# --------------------


def scan_sqs():
    findings = []

    try:
        resp = sqs.list_queues()
    except ClientError as e:
        findings.append({
            "service": "sqs",
            "resource_arn": "arn:aws:sqs:::account",
            "issue": "sqs_list_error",
            "severity": "LOW",
            "details": {
                "message": "Error listing SQS queues; see logs.",
                "error": str(e),
            },
        })
        return findings

    queue_urls = resp.get("QueueUrls", []) or []

    for qurl in queue_urls:
        try:
            attrs_resp = sqs.get_queue_attributes(
                QueueUrl=qurl,
                AttributeNames=["All"],
            )
        except ClientError as e:
            findings.append({
                "service": "sqs",
                "resource_arn": qurl,
                "issue": "sqs_get_attributes_error",
                "severity": "LOW",
                "details": {
                    "message": "Error getting SQS queue attributes; see logs.",
                    "error": str(e),
                },
            })
            continue

        attrs = attrs_resp.get("Attributes", {})
        arn = attrs.get("QueueArn", qurl)

        base = {
            "service": "sqs",
            "resource_arn": arn,
            "queue_url": qurl,
        }

        # Encryption
        kms_key = attrs.get("KmsMasterKeyId")
        sqs_managed_sse = attrs.get("SqsManagedSseEnabled") == "true"
        if not kms_key and not sqs_managed_sse:
            findings.append({
                **base,
                "issue": "sqs_encryption_missing",
                "severity": "MEDIUM",
                "details": {
                    "message": "SQS queue has no KMS CMK and SQS managed SSE is not enabled.",
                },
            })

        # Redrive policy (DLQ)
        if "RedrivePolicy" not in attrs:
            findings.append({
                **base,
                "issue": "sqs_no_redrive_policy",
                "severity": "LOW",
                "details": {
                    "message": "SQS queue has no redrive policy configured (no DLQ).",
                },
            })

    return findings


# --------------------
# MAIN HANDLER
# --------------------


def lambda_handler(event, context):
    scan_id = str(uuid.uuid4())
    started_at = _now_iso()

    scans_table.put_item(
        Item={
            "scan_id": scan_id,
            "timestamp": started_at,
            "status": "RUNNING",
            "resources_scanned": 0,
        }
    )

    all_findings = []

    # S3
    s3_findings = scan_s3_buckets()
    all_findings.extend(s3_findings)

    # IAM
    try:
        iam_findings = scan_iam()
        all_findings.extend(iam_findings)
    except Exception as e:
        all_findings.append({
            "service": "iam",
            "resource_arn": "arn:aws:iam:::account",
            "issue": "iam_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning IAM; see CloudWatch logs.",
                "error": str(e),
            },
        })

    # Transfer Family
    try:
        transfer_findings = scan_transfer_family()
        all_findings.extend(transfer_findings)
    except Exception as e:
        all_findings.append({
            "service": "transfer",
            "resource_arn": "arn:aws:transfer:::account",
            "issue": "transfer_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning AWS Transfer Family; see CloudWatch logs.",
                "error": str(e),
            },
        })

    # Lambda
    try:
        lambda_findings = scan_lambda_functions()
        all_findings.extend(lambda_findings)
    except Exception as e:
        all_findings.append({
            "service": "lambda",
            "resource_arn": "arn:aws:lambda:::account",
            "issue": "lambda_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning Lambda; see CloudWatch logs.",
                "error": str(e),
            },
        })

    # Step Functions
    try:
        stepfn_findings = scan_stepfunctions()
        all_findings.extend(stepfn_findings)
    except Exception as e:
        all_findings.append({
            "service": "stepfunctions",
            "resource_arn": "arn:aws:states:::account",
            "issue": "stepfn_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning Step Functions; see CloudWatch logs.",
                "error": str(e),
            },
        })

    # EventBridge
    try:
        eb_findings = scan_eventbridge()
        all_findings.extend(eb_findings)
    except Exception as e:
        all_findings.append({
            "service": "eventbridge",
            "resource_arn": "arn:aws:events:::account",
            "issue": "eventbridge_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning EventBridge; see CloudWatch logs.",
                "error": str(e),
            },
        })

    # SQS
    try:
        sqs_findings = scan_sqs()
        all_findings.extend(sqs_findings)
    except Exception as e:
        all_findings.append({
            "service": "sqs",
            "resource_arn": "arn:aws:sqs:::account",
            "issue": "sqs_scan_error",
            "severity": "LOW",
            "details": {
                "message": "Error while scanning SQS; see CloudWatch logs.",
                "error": str(e),
            },
        })

    completed_at = _now_iso()

    with findings_table.batch_writer() as batch:
        for idx, f in enumerate(all_findings, start=1):
            item = {
                "scan_id": scan_id,
                "finding_id": f"FIND-{idx:04d}",
                "service": f["service"],
                "resource_arn": f["resource_arn"],
                "issue": f["issue"],
                "severity": f["severity"],
                "details": json.dumps(f.get("details", {})),
                "created_at": completed_at,
            }
            batch.put_item(Item=item)

    s3.put_object(
        Bucket=FINDINGS_BUCKET,
        Key=f"scans/{scan_id}/findings.json",
        Body=json.dumps(
            {
                "scan_id": scan_id,
                "started_at": started_at,
                "completed_at": completed_at,
                "findings": all_findings,
            },
            default=str,
            indent=2,
        ).encode("utf-8"),
        ContentType="application/json",
    )

    scans_table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :status, resources_scanned = :cnt, completed_at = :completed",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "COMPLETED",
            ":cnt": len(all_findings),
            ":completed": completed_at,
        },
    )

    body = {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "findings_count": len(all_findings),
        "started_at": started_at,
        "completed_at": completed_at,
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
