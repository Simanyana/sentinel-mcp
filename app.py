import hmac
import json
import os
from datetime import datetime, timedelta, timezone

import boto3
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

mcp = MCPServer("sentinel")
REGION = os.environ.get("AWS_REGION", "us-east-1")


@mcp.tool()
def recent_signins(hours: int = 24, max_results: int = 20) -> dict:
    """List recent AWS console sign-in events from CloudTrail, with failures and sign-ins without MFA counted."""
    hours = max(1, min(hours, 168))
    max_results = max(1, min(max_results, 50))
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    resp = ct.lookup_events(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
        StartTime=start,
        MaxResults=max_results,
    )
    events = []
    for e in resp.get("Events", []):
        d = json.loads(e["CloudTrailEvent"])
        ident = d.get("userIdentity", {})
        extra = d.get("additionalEventData") or {}
        events.append({
            "time": d.get("eventTime"),
            "user": ident.get("userName") or ident.get("arn") or ident.get("type"),
            "user_type": ident.get("type"),
            "source_ip": d.get("sourceIPAddress"),
            "result": (d.get("responseElements") or {}).get("ConsoleLogin"),
            "mfa_used": extra.get("MFAUsed"),
            "region": d.get("awsRegion"),
        })
    return {
        "window_hours": hours,
        "total": len(events),
        "failed": sum(1 for x in events if x["result"] != "Success"),
        "success_without_mfa": sum(1 for x in events if x["result"] == "Success" and x["mfa_used"] == "No"),
        "events": events,
    }


@mcp.tool()
def security_findings(min_severity: int = 0, max_results: int = 10) -> dict:
    """List the most severe Amazon GuardDuty findings (sample data in this demo), highest severity first."""
    max_results = max(1, min(max_results, 50))
    gd = boto3.client("guardduty", region_name=REGION)
    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return {"error": "GuardDuty is not enabled in this region", "findings": []}
    did = detectors[0]
    ids = gd.list_findings(
        DetectorId=did,
        FindingCriteria={"Criterion": {"severity": {"GreaterThanOrEqual": int(min_severity)}}},
        SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
        MaxResults=max_results,
    ).get("FindingIds", [])
    if not ids:
        return {"total": 0, "findings": []}
    found = gd.get_findings(DetectorId=did, FindingIds=ids).get("Findings", [])
    out = []
    for f in found:
        out.append({
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "description": (f.get("Description") or "")[:300],
            "resource_type": (f.get("Resource") or {}).get("ResourceType"),
            "region": f.get("Region"),
            "last_seen": f.get("UpdatedAt"),
            "sample": "[SAMPLE]" in (f.get("Title") or "") or "111122223333" in (f.get("Description") or ""),
        })
    out.sort(key=lambda x: x["severity"] or 0, reverse=True)
    return {"total": len(out), "findings": out}


class TokenAuth(BaseHTTPMiddleware):
    """Reject every request that does not carry the secret bearer token."""

    async def dispatch(self, request, call_next):
        expected = os.environ.get("MCP_TOKEN", "")
        given = request.headers.get("authorization", "")
        if not expected or not hmac.compare_digest(given, "Bearer " + expected):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


app = mcp.streamable_http_app(
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
app.add_middleware(TokenAuth)
