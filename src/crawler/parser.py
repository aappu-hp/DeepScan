from __future__ import annotations
from bs4 import BeautifulSoup
from typing import List
from .models import Endpoint, FormInput
from ..utils.url import normalize_url

def extract_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    hrefs: List[str] = []
    for a in soup.find_all("a", href=True):
        norm = normalize_url(base_url, a["href"])
        if norm:
            hrefs.append(norm)
    return hrefs

def extract_title(html: str) -> str | None:
    soup = BeautifulSoup(html, "lxml")
    t = soup.find("title")
    return t.get_text(strip=True) if t else None

def extract_forms(base_url: str, html: str, depth: int, parent_url: str | None) -> List[Endpoint]:
    soup = BeautifulSoup(html, "lxml")
    endpoints: List[Endpoint] = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "GET").upper()
        form_url = normalize_url(base_url, action)
        if not form_url:
            continue

        inputs = []
        params = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            itype = inp.get("type")
            val = inp.get("value")
            inputs.append(FormInput(name=name, input_type=itype, value=val))
            if val is not None:
                params[name] = val

        endpoints.append(
            Endpoint(
                url=form_url,
                type="form",
                method=method,
                params=params,
                form_inputs=inputs,
                depth=depth,
                parent=parent_url,
                discovered_via="form",
            )
        )
    return endpoints

def extract_js_urls(base_url: str, html: str) -> List[str]:
    """
    Basic heuristic to find URLs inside inline JS. This is intentionally simple;
    for heavy JS-based apps you will later extend to fetch .js files and parse.
    """
    soup = BeautifulSoup(html, "lxml")
    candidates = []
    for script in soup.find_all("script"):
        content = script.string or ""
        # split on quotes and pick tokens that look like URLs
        for chunk in content.replace('"', "'").split("'"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk.startswith("http://") or chunk.startswith("https://") or chunk.startswith("/"):
                norm = normalize_url(base_url, chunk)
                if norm:
                    candidates.append(norm)
    return candidates
