# AEGIS - Agentic Exploit Generation in Isolated Sandboxes

## Experimental and explorative

As the name states: Agentic Exploit Generation in Isolated Sandboxes. The aim is to create an agentic AI testbed to check codebases (repos) for vulnerabilities (or candidates), generate exploit code and verify it in isolated sandboxes (containers).

In order to have something maintainable and flexible I opted for a Ports & Adapters pattern, also known as hexagonale architecture.

## Testdrive
I use uv, you may change things for pip/poetry:

1. Clone the repo
2. uv sync --group dev
3. uv run pytest