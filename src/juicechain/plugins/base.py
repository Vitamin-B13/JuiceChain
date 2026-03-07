from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from juicechain.core.input_point import Location

if TYPE_CHECKING:
    from juicechain.core.http_client import HttpClient
    from juicechain.core.input_point import InputPoint


@dataclass
class Finding:
    vuln_type: str
    severity: str
    evidence: str
    request: dict[str, Any]
    response: dict[str, Any]


class VulnPlugin(ABC):
    """Base class for all vulnerability plugins."""

    name: ClassVar[str]
    severity: ClassVar[str]
    supported_locations: ClassVar[set[Location]] = {"query", "body_form", "body_json"}

    @abstractmethod
    def check(
        self,
        base: str,
        point: "InputPoint",
        client: "HttpClient",
        timeout: float,
        max_bytes: int,
    ) -> Finding | None:
        """Run the check. Return Finding if vulnerable, None otherwise."""
        raise NotImplementedError
