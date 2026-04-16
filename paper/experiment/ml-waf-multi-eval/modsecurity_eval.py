from path_setup import ensure_ml_waf_imports
from http_utils import payload_to_request, request_surface


def modsec_blocks(payload: str, param: str = "id") -> bool:
    ensure_ml_waf_imports()
    from rules.modsecurity_sqli_regex import matched_rule_ids

    req = payload_to_request(payload, param)
    full = request_surface(req)
    return len(matched_rule_ids(full)) > 0
