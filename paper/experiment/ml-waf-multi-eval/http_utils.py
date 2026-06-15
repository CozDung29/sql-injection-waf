def payload_to_request(payload: str, param: str = "id") -> dict:
    return {
        "method": "GET",
        "path": "/api",
        "query": f"{param}={payload}",
        "headers": {},
        "body": "",
    }


def request_surface(req: dict) -> str:
    p = (req.get("path") or "") + (req.get("query") or "")
    b = req.get("body") or ""
    return p + " " + b
