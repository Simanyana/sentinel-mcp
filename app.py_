import hmac
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel")

mcp = MCPServer("sentinel")

REGION = os.environ.get("AWS_REGION", "us-east-1")
# Sentinel queries ConsoleLogin events in this one region only. Sign-ins recorded
# in other regions are not covered, and the tool output says so.
CLOUDTRAIL_REGION = os.environ.get("CLOUDTRAIL_REGION", "us-east-1")
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "global.anthropic.claude-haiku-4-5-20251001-v1:0")
MAX_CLOUDTRAIL_PAGES = 3
EVIDENCE_ID_RE = re.compile(r"\b(?:signin|finding)-\d{3}\b")


def _error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    return type(exc).__name__


def _sentinel_priority(severity):
    """Application triage priority. This is not GuardDuty's severity label."""
    if severity is None:
        return "Unknown"
    if severity >= 7:
        return "High"
    if severity >= 4:
        return "Medium"
    return "Low"


def _finding_provenance(finding):
    """Return sample=True only when GuardDuty's own metadata says so. Otherwise None."""
    service = finding.get("Service") or {}
    additional = service.get("AdditionalInfo") or {}

    raw_sample = additional.get("sample")

    # Some API representations encode additional metadata as JSON text.
    raw_value = additional.get("Value")
    if raw_sample is None and isinstance(raw_value, str):
        try:
            parsed = json.loads(raw_value)
        except (TypeError, ValueError):
            parsed = {}
        if isinstance(parsed, dict):
            raw_sample = parsed.get("sample")

    if raw_sample is True or (isinstance(raw_sample, str) and raw_sample.strip().lower() == "true"):
        return {"sample": True, "provenance": "GuardDuty sample metadata"}

    title = finding.get("Title") or ""
    if title.startswith("[SAMPLE]"):
        return {"sample": True, "provenance": "GuardDuty sample title prefix"}

    # "Not found" is not the same as "real". Keep it unverified.
    return {"sample": None, "provenance": "unverified"}


def _signin_counts(events):
    successful = sum(1 for x in events if x["result"] == "Success")
    failed = sum(1 for x in events if x["result"] == "Failure")
    return {
        "successful": successful,
        "failed": failed,
        "unknown": len(events) - successful - failed,
        "successful_without_mfa": sum(
            1 for x in events if x["result"] == "Success" and x["mfa_used"] == "No"
        ),
        "root_signins": sum(1 for x in events if x["user_type"] == "Root"),
    }


def _signins(hours, max_results):
    hours = max(1, min(int(hours), 168))
    max_results = max(1, min(int(max_results), 50))
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    scope = {
        "source": "CloudTrail LookupEvents (ConsoleLogin)",
        "queried_region": CLOUDTRAIL_REGION,
        "window_hours": hours,
        "window_start_utc": start.isoformat(),
        "coverage_note": (
            "Only ConsoleLogin events retrieved from this region are included. "
            "Sign-ins recorded in other regions are not covered."
        ),
    }

    raw, next_token, pages = [], None, 0
    try:
        ct = boto3.client("cloudtrail", region_name=CLOUDTRAIL_REGION)
        while True:
            kwargs = {
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
                "StartTime": start,
                "MaxResults": min(50, max_results - len(raw)),
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = ct.lookup_events(**kwargs)
            raw.extend(resp.get("Events", []))
            next_token = resp.get("NextToken")
            pages += 1
            if not next_token or len(raw) >= max_results or pages >= MAX_CLOUDTRAIL_PAGES:
                break
    except (ClientError, BotoCoreError) as exc:
        logger.error("CloudTrail lookup failed: %s", _error_code(exc))
        return {
            "status": "unavailable",
            "data_mode": "not checked",
            "retrieved_count": 0,
            "truncated": False,
            "scope": scope,
            "warnings": ["CloudTrail sign-in events could not be checked."],
            "error_code": _error_code(exc),
            **_signin_counts([]),
            "events": [],
        }

    warnings, events, skipped = [], [], 0
    for e in raw[:max_results]:
        try:
            d = json.loads(e["CloudTrailEvent"])
        except (KeyError, TypeError, ValueError):
            skipped += 1
            continue
        ident = d.get("userIdentity") or {}
        extra = d.get("additionalEventData") or {}
        result = (d.get("responseElements") or {}).get("ConsoleLogin")
        events.append({
            "id": "signin-%03d" % (len(events) + 1),
            "time": d.get("eventTime"),
            "user": ident.get("userName") or ident.get("arn") or ident.get("type"),
            "user_type": ident.get("type"),
            "source_ip": d.get("sourceIPAddress"),
            "result": result if result in ("Success", "Failure") else "unknown",
            "mfa_used": extra.get("MFAUsed"),
            "region": d.get("awsRegion"),
        })

    if skipped:
        warnings.append("%d sign-in record(s) could not be read and were left out." % skipped)
    truncated = next_token is not None
    if truncated:
        warnings.append(
            "More sign-in events exist in this window; only the first %d were retrieved." % len(events)
        )

    return {
        "status": "partial" if truncated else "ok",
        "data_mode": "live",
        "retrieved_count": len(events),
        "truncated": truncated,
        "scope": scope,
        "warnings": warnings,
        **_signin_counts(events),
        "events": events,
    }


def _unavailable_findings(scope, warning, code):
    return {
        "status": "unavailable",
        "data_mode": "not checked",
        "retrieved_count": 0,
        "truncated": False,
        "scope": scope,
        "warnings": [warning],
        "error_code": code,
        "findings": [],
    }


def _findings(min_severity, max_results):
    min_severity = max(0, min(int(min_severity), 10))
    max_results = max(1, min(int(max_results), 50))
    scope = {
        "source": "Amazon GuardDuty",
        "queried_region": REGION,
        "min_severity": min_severity,
        "retrieval": "top %d at or above severity %d, highest first" % (max_results, min_severity),
        "coverage_note": "Only findings from this region's first detector, at or above the minimum severity, are included.",
    }

    try:
        gd = boto3.client("guardduty", region_name=REGION)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return _unavailable_findings(
                scope,
                "GuardDuty is not enabled in this region, so findings could not be checked.",
                "NoDetector",
            )
        did = detectors[0]
        resp = gd.list_findings(
            DetectorId=did,
            FindingCriteria={"Criterion": {"severity": {"GreaterThanOrEqual": min_severity}}},
            SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
            MaxResults=max_results,
        )
        ids = resp.get("FindingIds", [])
        more = bool(resp.get("NextToken"))
        found = gd.get_findings(DetectorId=did, FindingIds=ids).get("Findings", []) if ids else []
    except (ClientError, BotoCoreError) as exc:
        logger.error("GuardDuty check failed: %s", _error_code(exc))
        return _unavailable_findings(scope, "GuardDuty could not be checked.", _error_code(exc))

    out = []
    for f in found:
        sev = f.get("Severity")  # kept as None when missing; never replaced with 0
        prov = _finding_provenance(f)
        out.append({
            "type": f.get("Type"),
            "title": f.get("Title"),
            "description": (f.get("Description") or "")[:300],
            "source_severity": sev,
            "sentinel_review_priority": _sentinel_priority(sev),
            "priority_basis": "Sentinel triage rule applied to the GuardDuty severity score. It is not proof of compromise.",
            "sample": prov["sample"],
            "data_provenance": prov["provenance"],
            "resource_type": (f.get("Resource") or {}).get("ResourceType"),
            "region": f.get("Region"),
            "last_seen": f.get("UpdatedAt"),
        })

    # Highest known severity first; findings without a severity go last.
    out.sort(key=lambda x: (x["source_severity"] is not None, x["source_severity"] or 0), reverse=True)
    for i, x in enumerate(out, start=1):
        x["id"] = "finding-%03d" % i

    warnings = []
    if more:
        warnings.append("More findings exist; only the top %d were retrieved." % len(out))
    if any(x["sample"] is not True for x in out):
        warnings.append(
            "Some findings have unverified provenance. Do not present them as live attacks or as sample data."
        )

    if not out:
        data_mode = "none"
    elif all(x["sample"] is True for x in out):
        data_mode = "sample"
    else:
        data_mode = "mixed or unverified"

    return {
        "status": "partial" if more else "ok",
        "data_mode": data_mode,
        "retrieved_count": len(out),
        "truncated": more,
        "scope": scope,
        "warnings": warnings,
        "findings": out,
    }


def _template_briefing(si, fi):
    sign_ok = si["status"] != "unavailable"
    find_ok = fi["status"] != "unavailable"
    min_sev = fi["scope"].get("min_severity", 0)
    parts = []

    if sign_ok:
        parts.append(
            "What happened: %d sign-in events retrieved from the last %d hours "
            "(%d failed, %d unknown, %d without MFA, %d as root)."
            % (
                si["retrieved_count"],
                si["scope"]["window_hours"],
                si["failed"],
                si["unknown"],
                si["successful_without_mfa"],
                si["root_signins"],
            )
        )
    else:
        parts.append("What happened: CloudTrail sign-ins could not be checked.")

    top_sev = None
    if not find_ok:
        parts.append("GuardDuty could not be checked.")
    elif fi["findings"]:
        top = fi["findings"][0]
        top_sev = top["source_severity"]
        details = ["severity %s" % top_sev if top_sev is not None else "severity not reported"]
        details.append("demo data" if top["sample"] is True else "provenance unverified")
        parts.append("Top GuardDuty finding: %s (%s)." % (top["title"], ", ".join(details)))
    else:
        parts.append("GuardDuty was checked and found nothing at severity %d or higher." % min_sev)

    high_signin = sign_ok and (si["failed"] > 0 or si["successful_without_mfa"] > 0)
    medium_signin = sign_ok and si["root_signins"] > 0
    unrated_finding = find_ok and bool(fi["findings"]) and top_sev is None

    if high_signin or (top_sev is not None and top_sev >= 7):
        level = "High"
        nxt = "Review the failed or no-MFA sign-ins and the highest-severity finding first."
    elif medium_signin or (top_sev is not None and top_sev >= 4):
        level = "Medium"
        nxt = "Confirm the root sign-ins were expected, then review the top finding."
    elif sign_ok and find_ok and not unrated_finding:
        level = "Low"
        nxt = "Keep routine monitoring."
    else:
        level = "Incomplete"
        nxt = "Fix the unavailable source or the missing severity, then run the check again before deciding."

    if si.get("truncated") or fi.get("truncated"):
        nxt += " Coverage is partial, so more events or findings may exist."

    parts.append("Severity: %s." % level)
    parts.append("Next step: %s" % nxt)
    return " ".join(parts)


@mcp.tool()
def recent_signins(hours: int = 24, max_results: int = 20) -> dict:
    """List recent AWS console sign-in events from CloudTrail in the queried region. Counts cover retrieved events only."""
    return _signins(hours, max_results)


@mcp.tool()
def security_findings(min_severity: int = 0, max_results: int = 10) -> dict:
    """List the top Amazon GuardDuty findings by severity. Each finding shows its provenance; sample findings are not live attacks."""
    return _findings(min_severity, max_results)


@mcp.tool()
def security_briefing(hours: int = 24) -> dict:
    """Plain-English briefing from CloudTrail sign-ins and GuardDuty findings at severity 7 or higher, with evidence IDs, source status and the briefing source (AI or fallback)."""
    activity = []
    si = _signins(hours, 20)
    activity.append("Checked sign-in observations (status: %s)" % si["status"])
    fi = _findings(7, 5)
    activity.append("Retrieved GuardDuty findings at severity 7 or higher (status: %s)" % fi["status"])

    facts = {"cloudtrail_signins": si, "guardduty_findings": fi}
    valid_ids = {e["id"] for e in si["events"]} | {f["id"] for f in fi["findings"]}

    prompt = (
        "You are a security assistant for a beginner. Use ONLY the JSON facts below. "
        "Write under 150 words with these labelled parts: What happened; Review priority and its basis; "
        "Evidence IDs (cite only IDs that appear in the facts, such as signin-001 or finding-001); "
        "What remains unknown; Next investigation step. "
        "If a source has status unavailable, say it could not be checked and never say there are no threats. "
        "If a finding has sample=true, say it is demo data. If sample is null, say its origin is unverified. "
        "State that GuardDuty findings were checked only at severity 7 or higher. "
        "Do not infer a relationship between events unless the facts show a matching user or time. "
        "Do not invent facts.\n\nFACTS:\n" + json.dumps(facts, default=str)
    )

    text, mode, source = None, "fallback", None
    try:
        br = boto3.client("bedrock-runtime", region_name=REGION)
        r = br.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 500},
        )
        blocks = r["output"]["message"]["content"]
        candidate = " ".join(b["text"] for b in blocks if "text" in b).strip()
        if not candidate:
            raise ValueError("empty model reply")
        unknown_refs = sorted(set(EVIDENCE_ID_RE.findall(candidate)) - valid_ids)
        if unknown_refs:
            raise ValueError("unknown evidence IDs: " + ", ".join(unknown_refs))
        text, mode, source = candidate, "ai", "bedrock:" + MODEL_ID
    except (ClientError, BotoCoreError) as exc:
        logger.error("Bedrock call failed: %s", _error_code(exc))
        source = "template (Bedrock unavailable: %s)" % _error_code(exc)
    except Exception as exc:
        logger.error("AI briefing rejected: %s", exc)
        source = "template (AI output rejected)"

    if text is None:
        text = _template_briefing(si, fi)
    activity.append("Prepared briefing (%s)" % mode)

    return {"briefing": text, "mode": mode, "source": source, "activity": activity, "facts": facts}


class TokenAuth(BaseHTTPMiddleware):
    """Reject every request that does not carry the secret bearer token."""

    async def dispatch(self, request, call_next):
        expected = os.environ.get("MCP_TOKEN", "")
        given = request.headers.get("authorization", "")
        wanted = "Bearer " + expected
        if not expected or not hmac.compare_digest(given.encode(), wanted.encode()):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


app = mcp.streamable_http_app(
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
app.add_middleware(TokenAuth)
