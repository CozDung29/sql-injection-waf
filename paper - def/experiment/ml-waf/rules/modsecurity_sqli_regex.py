import re

MODSECURITY_SQLI_REGEX = [
    ("942160", r"(?i:sleep\(\s*?\d*?\s*?\)|benchmark\(.*?\,.*?\))"),
    ("942170", r"(?i:(?:select|;)\s+(?:benchmark|sleep|if)\s*?\(\s*?\(?\s*?\w+)"),
    ("942220", r"(?i:-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|3\.0\.00738585072007e-308|1e309)"),
    ("942230", r"(?i:[\s()]case\s*?\(|\)\s*?like\s*?\(|having\s*?[^\s]+\s*?[^\w\s]|if\s?\([\d\w]\s*?[=<>~])"),
    ("942240", r"(?i:[\"'`](?:;*\s*?waitfor\s+(?:delay|time)\s+[\"'`]|;.*?:\s*?goto)|alter\s*?\w+.*?cha(?:racte)?r\s+set\s+\w+)"),
    ("942250", r"(?i:merge.*?using\s*?\(|execute\s*?immediate\s*?[\"'`]|match\s*?[\w(),+-]+\s*?against\s*?\()"),
    ("942270", r"(?i)union.*?select.*?from"),
    ("942280", r"(?i:(?:;\s*?shutdown\s*?(?:[#;]|\/\*|--|\{)|waitfor\s*?delay\s?[\"'`]+\s?\d|select\s*?pg_sleep))"),
    ("942290", r"(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))"),
    ("942320", r"(?i:(?:create\s+(?:procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-|;\s*?(?:declare|open)\s+[\w-]+|procedure\s+analyse\s*?\(|declare[^\w]+[@#]\s*?\w+|exec\s*?\(\s*?\@))"),
    ("942500", r"(?i:/\*[!+](?:[\w\s=_\-()]+)?\*/)"),
    ("942110", r"(?:^\s*[\"'`;]+|[\"'`]+\s*$)"),
    ("942300", r"(?i:(?:(?:n(?:and|ot)|(?:x?x)?or|between|\|\||like|and|div|&&)\s+\s*?\w+\(|\)\s*?when\s*?\d+\s*?then|[\"'`]\s*?(?:--|\{|#)|cha?r\s*?\(\s*?\d|\/\*!\s?\d+))"),
    ("942140", r"(?i:\b(?:(?:m(?:s(?:ys(?:ac(?:cess(?:objects|storage|xml)|es)|(?:relationship|object|querie)s|modules2?)|db)|aster\.\.sysdatabases|ysql\.db)|pg_(?:catalog|toast)|information_schema|northwind|tempdb)\b|s(?:(?:ys(?:\.database_name|aux)|qlite(?:_temp)?_master)\b|chema(?:_name\b|\W*\())|d(?:atabas|b_nam)e\W*\())"),
    ("942190", r"(?i:(?:[\"'`](?:;?\s*?(?:having|select|union)\b\s*?[^\s]|\s*?!\s*?[\"'`\w])|(?:c(?:onnection_id|urrent_user)|database)\s*?\([^\)]*?|u(?:nion(?:[\w(\s]*?select| select @)|ser\s*?\([^\)]*?)|s(?:chema\s*?\([^\)]*?|elect.*?\w?user\()|into[\s+]+(?:dump|out)file\s*?[\"'`]|\s*?exec(?:ute)?.*?\Wxp_cmdshell|from\W+information_schema\W|exec(?:ute)?\s+master\.|\wiif\s*?\())"),
]

_compiled = [(rid, re.compile(pat)) for rid, pat in MODSECURITY_SQLI_REGEX]


def count_matches(text: str) -> int:
    if not text:
        return 0
    n = 0
    for _, pattern in _compiled:
        if pattern.search(text):
            n += 1
    return n


def matched_rule_ids(text: str) -> list[str]:
    if not text:
        return []
    return [rid for rid, pattern in _compiled if pattern.search(text)]
