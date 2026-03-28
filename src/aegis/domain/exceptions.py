# src/domain/exceptions.py
# I want to avoid generic python errors
# TODO make sure the outer layers know how
# to catch these things (in my hexa ardh)

class SecurityAgentError(Exception):
    """Base exception for all domain-level errors."""
    pass

class InvalidStateTransitionError(SecurityAgentError):
    """Raise when the agent tries to move to an invalid state."""
    pass

class InvalidTaintPathError(SecurityAgentError):
    """Raised when a taint path is logically impossible (e.g. sink before source)."""
    pass