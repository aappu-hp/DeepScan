from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

@dataclass
class FormInput:
    name: str
    input_type: Optional[str] = None
    value: Optional[str] = None

@dataclass
class Endpoint:
    url: str
    type: str = "page"                 # "page" or "form"
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    form_inputs: List[FormInput] = field(default_factory=list)
    depth: int = 0
    parent: Optional[str] = None
    discovered_via: str = "link"       # link|form|script|seed
    status: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
