from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Location = Literal["query", "body_form", "body_json", "header", "cookie", "path_segment"]


@dataclass
class InputPoint:
    method: str
    path: str
    location: Location
    param: str
    original_value: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
