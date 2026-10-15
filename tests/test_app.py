"""Automated tests for the Sentinel MCP server logic.

Every AWS and Bedrock call is replaced by a fake, so these tests never touch a real account.
Run from the repository root with:  python -m pytest -q
"""
import json

from botocore.exceptions import ClientError

import app as sentinel


def cloudtrail_event(result="Success", user_type="IAMUser", mfa="Yes", user="alice"):
    response = {"ConsoleLogin": result} if result is not None else None
    return {
        "CloudTrailEvent": json.dumps({
            "eventTime": "2026-10-15T08:00:00Z",
            "userIdentity": {"type": user_type, "userName": user},
            "sourceIPAddress": "203.0.113.5",
            "responseElements": response,
            "additionalEventData": {"MFAUsed": mfa},
            "awsRegion": "us-east-1",
        })
    }


class FakeCloudTrail:
    """Returns one page per lookup_events call, in order."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    def lookup_events(self, **kwargs):
        page = self.pages[self.calls]
        self.calls += 1
        return page


class BrokenCloudTrail:
    def lookup_events(self, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, "LookupEvents")


class FakeGuardDuty:
    def __init__(self, findings, detectors=("det-1",), next_token=None, fail=None):
        self.findings = findings
        self.detectors = detectors
        self.next_token = next_token
        self.fail = fail

    def list_detectors(self):
        if self.fail is not None:
            raise self.fail
        return {"DetectorIds": list(self.detectors)}

    def list_findings(self, **kwargs):
        resp = {"FindingIds": ["f%d" % i for i in range(len(self.findings))]}
        if self.next_token:
            resp["NextToken"] = self.next_token
        return resp

    def get_findings(self, **kwargs):
        return {"Findings": self.findings}


class FakeBedrock:
    def __init__(self, text=None, error=None):
        self.text = text
        self.error = error

    def converse(self, **kwargs):
        if self.error is not None:
            raise self.error
        return {"output": {"message": {"content": [{"text": self.text}]}}}


def install(monkeypatch, services):
    """Make boto3.client return the fake for each service name."""
    monkeypatch.setattr(sentinel.boto3, "client", lambda name, **kwargs: services[name])


# ---- Sign-in events -------------------------------------------------------

def test_signin_counts_keep_success_failure_and_unknown_apart(monkeypatch):
    events = [cloudtrail_event("Success"), cloudtrail_event("Failure"), cloudtrail_event(None)]
    install(monkeypatch, {"cloudtrail": FakeCloudTrail([{"Events": events}])})
    r = sentinel._signins(24, 20)
    assert (r["successful"], r["failed"], r["unknown"]) == (1, 1, 1)
    assert r["retrieved_count"] == 3
    assert r["status"] == "ok" and r["truncated"] is False
    assert "queried_region" in r["scope"]
    assert "coverage_note" in r["scope"]


def test_signin_without_mfa_and_root_are_counted(monkeypatch):
    events = [
        cloudtrail_event("Success", mfa="No"),
        cloudtrail_event("Success", user_type="Root", mfa="Yes"),
    ]
    install(monkeypatch, {"cloudtrail": FakeCloudTrail([{"Events": events}])})
    r = sentinel._signins(24, 20)
    assert r["successful_without_mfa"] == 1
    assert r["root_signins"] == 1


def test_signins_report_partial_when_more_pages_exist(monkeypatch):
    page = {"Events": [cloudtrail_event()], "NextToken": "more"}
    install(monkeypatch, {"cloudtrail": FakeCloudTrail([page, page])})
    r = sentinel._signins(24, 2)
    assert r["retrieved_count"] == 2
    assert r["truncated"] is True
    assert r["status"] == "partial"


def test_cloudtrail_failure_is_unavailable_not_zero(monkeypatch):
    install(monkeypatch, {"cloudtrail": BrokenCloudTrail()})
    r = sentinel._signins(24, 20)
    assert r["status"] == "unavailable"
    assert r["error_code"] == "AccessDenied"
    assert r["retrieved_count"] == 0
    assert "could not be checked" in r["warnings"][0]


# ---- Sample provenance ----------------------------------------------------

def test_sample_only_when_guardduty_metadata_says_so():
    assert sentinel._finding_provenance({"Service": {"AdditionalInfo": {"sample": True}}})["sample"] is True
    assert sentinel._finding_provenance({"Title": "[SAMPLE] demo"})["sample"] is True
    encoded = {"Service": {"AdditionalInfo": {"Value": '{"sample": true}'}}}
    assert sentinel._finding_provenance(encoded)["sample"] is True


def test_unmarked_finding_stays_unverified_even_with_sample_account_number():
    result = sentinel._finding_provenance({"Title": "x", "Description": "account 111122223333"})
    assert result == {"sample": None, "provenance": "unverified"}


# ---- Priority and findings ------------------------------------------------

def test_missing_severity_is_unknown_not_low():
    assert sentinel._sentinel_priority(None) == "Unknown"
    assert sentinel._sentinel_priority(9.0) == "High"
    assert sentinel._sentinel_priority(4) == "Medium"
    assert sentinel._sentinel_priority(2) == "Low"


def test_findings_sorted_highest_first_with_unknown_severity_last(monkeypatch):
    findings = [
        {"Title": "unrated", "Severity": None},
        {"Title": "low", "Severity": 3.0},
        {"Title": "critical", "Severity": 8.0, "Service": {"AdditionalInfo": {"sample": True}}},
    ]
    install(monkeypatch, {"guardduty": FakeGuardDuty(findings)})
    r = sentinel._findings(0, 10)
    assert [f["title"] for f in r["findings"]] == ["critical", "low", "unrated"]
    assert r["findings"][0]["id"] == "finding-001"
    assert r["findings"][0]["sample"] is True
    assert r["findings"][1]["sample"] is None
    assert r["data_mode"] == "mixed or unverified"


def test_guardduty_error_is_unavailable_not_no_threats(monkeypatch):
    error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListDetectors")
    install(monkeypatch, {"guardduty": FakeGuardDuty([], fail=error)})
    r = sentinel._findings(7, 5)
    assert r["status"] == "unavailable"
    assert r["findings"] == []
    assert "could not be checked" in r["warnings"][0]


def test_truncated_findings_are_reported(monkeypatch):
    findings = [{"Title": "a", "Severity": 8.0}]
    install(monkeypatch, {"guardduty": FakeGuardDuty(findings, next_token="more")})
    r = sentinel._findings(7, 5)
    assert r["status"] == "partial"
    assert r["truncated"] is True


# ---- Fallback briefing (rule-based text) ----------------------------------

def ok_signins(**overrides):
    base = {
        "status": "ok", "retrieved_count": 3, "scope": {"window_hours": 24},
        "failed": 0, "unknown": 0, "successful_without_mfa": 0, "root_signins": 0,
        "truncated": False,
    }
    base.update(overrides)
    return base


def findings_result(findings=None, status="ok", min_severity=7):
    return {
        "status": status, "scope": {"min_severity": min_severity},
        "truncated": False, "findings": findings or [],
    }


def test_unrated_finding_gives_incomplete_not_low():
    fi = findings_result([{"title": "T", "source_severity": None, "sample": None}])
    assert "Severity: Incomplete" in sentinel._template_briefing(ok_signins(), fi)


def test_no_findings_states_the_severity_threshold_checked():
    text = sentinel._template_briefing(ok_signins(), findings_result())
    assert "severity 7 or higher" in text
    assert "Severity: Low" in text


def test_unavailable_cloudtrail_never_reads_as_low():
    text = sentinel._template_briefing(ok_signins(status="unavailable"), findings_result())
    assert "could not be checked" in text
    assert "Severity: Incomplete" in text


def test_demo_finding_is_labelled_as_demo_data():
    fi = findings_result([{"title": "Bad", "source_severity": 9.0, "sample": True}])
    text = sentinel._template_briefing(ok_signins(), fi)
    assert "Severity: High" in text
    assert "demo data" in text


# ---- Full briefing: AI versus fallback ------------------------------------

def install_briefing_sources(monkeypatch, bedrock):
    install(monkeypatch, {
        "cloudtrail": FakeCloudTrail([{"Events": [cloudtrail_event()]}]),
        "guardduty": FakeGuardDuty([]),
        "bedrock-runtime": bedrock,
    })


def test_briefing_uses_ai_when_evidence_ids_are_valid(monkeypatch):
    install_briefing_sources(monkeypatch, FakeBedrock(text="What happened: one sign-in (signin-001)."))
    r = sentinel.security_briefing(hours=24)
    assert r["mode"] == "ai"
    assert r["source"].startswith("bedrock:")
    assert r["activity"][-1] == "Prepared briefing (ai)"


def test_briefing_falls_back_when_model_cites_unknown_evidence(monkeypatch):
    install_briefing_sources(monkeypatch, FakeBedrock(text="Evidence: signin-999"))
    r = sentinel.security_briefing(hours=24)
    assert r["mode"] == "fallback"
    assert "AI output rejected" in r["source"]


def test_briefing_falls_back_when_bedrock_errors(monkeypatch):
    error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "Converse")
    install_briefing_sources(monkeypatch, FakeBedrock(error=error))
    r = sentinel.security_briefing(hours=24)
    assert r["mode"] == "fallback"
    assert "ThrottlingException" in r["source"]
    assert r["briefing"]
