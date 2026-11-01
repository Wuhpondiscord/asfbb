import json,base64
from app.jwtcheck import inspect_jwt
def part(x):
    return base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
def test_safe_inspection():
    r=inspect_jwt(part({"alg":"none"})+"."+part({"sub":"secret"})+".x")
    assert r["signature_verified"] is False
    assert "secret" not in str(r)
    assert r["findings"]
