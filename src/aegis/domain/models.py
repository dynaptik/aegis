# src/domain/models.py
# Only initial data containers, probably needs more work
# TODO have a AI model analyse this and expand the model


from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field, model_validator

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CodeLocation(BaseModel):
    """Represents a specific physical location in the codebase."""
    file_path: str
    start_line: int
    end_line: int
    snippet: str

    @model_validator(mode='after')
    def check_line_numbers(self):
        if self.start_line > self.end_line:
            # TODO I need to create something in src/domain/exceptions for this
            raise ValueError("start_line cannot be greater than end_line")
        return self

class TaintPath(BaseModel):
    """Represents the flow of malicious input from source to sink"""
    source: CodeLocation = Field(description="Where the untrusted input enters")
    sink: CodeLocation = Field(description="Where the input is executed or stored dangerously")
    intermediary_steps: List[CodeLocation] = Field(default_factory=list)

class Vulnerability(BaseModel):
    """The core entity representing a discovered flaw."""
    id: str = Field(description="Internal tracking ID for the finding")
    cwe_id: str = Field(description="Common Weakness Enumeration ID (e.g., CWE-79)")
    title: str
    description: str
    severity: Severity
    taint_path: Optional[TaintPath] = None
    is_verified: bool = Field(default=False, description="True if the sandbox exploit succeeded")

    @property
    def dedup_key(self) -> str:
        """Identity key for deduplication: CWE + normalized title."""
        normalized = self.title.lower().replace("'", "").replace('"', "").split()
        return f"{self.cwe_id}|{' '.join(normalized)}"
