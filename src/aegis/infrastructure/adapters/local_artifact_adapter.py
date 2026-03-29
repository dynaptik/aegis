# src/aegis/infrastructure/adapters/local_artifact_adapter.py

# TODO implement this

from aegis.ports.artifact import IArtifactStore

class LocalArtifactAdapter(IArtifactStore):
    """This adapter writes the exploit to a safe directory with a generated README.md"""
    