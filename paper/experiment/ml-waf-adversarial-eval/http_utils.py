def payload_to_request(payload: str, param: str = "id") -> dict:
    return {
        "method": "GET",
        "path": "/api",
        "query": f"{param}={payload}",
        "headers": {},
        "body": "",
    }
