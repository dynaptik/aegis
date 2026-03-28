# src/domain/exceptions.py
# I want to avoid generic python errors
# TODO make sure the outer layers know how
# to catch these things (in my hexa ardh)

class SecurityAgentError(Exception):
    """Base exception for all domain-level errors."""

class InvalidStateTransitionError(SecurityAgentError):
    """Raise when the agent tries to move to an invalid state."""

class InvalidTaintPathError(SecurityAgentError):
    """Raised when a taint path is logically impossible (e.g. sink before source)."""

class ScannerError(SecurityAgentError):
    """Raised when the code scanner fails."""

class LlmError(SecurityAgentError):
    """Raised when LLM interaction fails (API error, malformed response)."""

class SandboxError(SecurityAgentError):
    """Raised when sandbox operations fail (setup, execution, teardown)."""
