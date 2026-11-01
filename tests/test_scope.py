from app.scope import parse_csv, classify, target_url
import pytest

def test_hackerone_table():
    csv = b"Asset name,Type,Max. severity,Bounty,Resolved Reports,Description\nweb.example.org,Domain,Critical,Eligible,24 (3%),Main app\n*.example.org,Other,High,Eligible,7 (1%),internal services\ncom.example.android,Android: Play Store,Critical,Eligible,72,app\n"
    a = parse_csv(csv)
    assert a[0]["compatibility"] == "web"
    assert a[0]["resolved_reports"] == 24
    assert a[0]["bounty"] is True
    assert a[1]["compatibility"] == "manual"
    assert a[2]["compatibility"] == "manual"

def test_url_and_credential_handling():
    assert classify("https://api.example.org/v1/", "URL") == "web"
    assert classify("https://name:pass@example.org", "URL") == "manual"
    assert classify("localhost", "Domain") == "manual"
    assert classify("*.example.org", "Domain") == "manual"
    with pytest.raises(ValueError):
        target_url({"name": "*.example.org", "compatibility": "manual"})

def test_unknown_and_headers():
    a = parse_csv(b"asset_identifier,asset_type,eligible_for_bounty,eligible_for_submission,max_severity\na.example.org,DOMAIN,true,false,high\n")
    assert a[0]["bounty"] is True
    assert a[0]["submission"] is False
    assert a[0]["max_severity"] == "high"
