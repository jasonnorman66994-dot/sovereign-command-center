from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field


SeverityLevel = Literal["info", "warning", "critical"]


class TelemetryPacket(BaseModel):
    module: str
    event: str
    severity: SeverityLevel = "info"
    timestamp: float = Field(default_factory=time.time)
    payload: dict[str, Any] = Field(default_factory=dict)
