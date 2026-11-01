import base64,json,time
def inspect_jwt(token):
    parts=token.split(".")
    if len(parts)!=3 or len(token)>16000: raise ValueError("Expected compact three-part JWT")
    try:
        header,claims=[json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))) for p in parts[:2]]
    except (ValueError,UnicodeDecodeError) as exc:
        raise ValueError("Malformed token") from exc
    if not isinstance(header,dict) or not isinstance(claims,dict): raise ValueError("JWT data must be objects")
    findings=[]
    if str(header.get("alg","")).lower()=="none": findings.append("Unsigned JWT header; verify server rejects this")
    if "exp" not in claims: findings.append("No exp claim; review expected lifetime policy")
    if any(k in header for k in ("jku","x5u")): findings.append("Remote key reference; ensure strict key allowlisting")
    if isinstance(claims.get("exp"),(int,float)) and claims["exp"]<time.time(): findings.append("Expired according to token claims")
    return {"algorithm":header.get("alg"),"header_fields":sorted(header),"claim_names":sorted(claims),"findings":findings,"signature_verified":False}
