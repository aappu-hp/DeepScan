from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ContextType(str, Enum):
    HTML_BODY      = "html_body"
    ATTR_DOUBLE    = "attr_double_quoted"
    ATTR_SINGLE    = "attr_single_quoted"
    ATTR_UNQUOTED  = "attr_unquoted"
    JS_STRING      = "js_string"
    JS_BLOCK       = "js_block"
    HTML_COMMENT   = "html_comment"
    URI            = "uri_context"
    HEADER         = "http_header"
    ENCODED        = "encoded_inert"
    NONE           = "no_reflection"


@dataclass
class ReflectionContext:
    parameter: str
    context_type: ContextType
    reflected: bool = False
    # which structural chars survived un-encoded, e.g. {"<": True, '"': False}
    survives: dict[str, bool] = field(default_factory=dict)
    snippet: Optional[str] = None        # ~80 chars around the reflection
    position: Optional[int] = None       # byte offset in the response
    exploitable_hint: bool = False       # did the break-out chars survive?
