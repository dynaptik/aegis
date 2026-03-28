# src/aegis/infrastructure/adapters/docker_sandbox.py

import logging
import subprocess
import uuid

from aegis.domain.exceptions import SandboxError
from aegis.ports.sandbox import ExecutionResult, IExploitSandbox

logger = logging.getLogger(__name__)

_DOCKER_IMAGE = "python:3.12-slim"


class DockerSandbox(IExploitSandbox):
    """Runs exploit scripts inside an isolated Docker container."""

    def __init__(self, image: str = _DOCKER_IMAGE, network: bool = False):
        self.image = image
        self.network = network
        self._container_name: str | None = None
        self._ready = False

    def setup_environment(self, repo_url: str, commit_hash: str) -> bool:
        self._container_name = f"aegis-sandbox-{uuid.uuid4().hex[:12]}"
        network_mode = "bridge" if self.network else "none"

        logger.info("Starting sandbox container …")
        try:
            # start a long-lived container that we exec into later
            subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", self._container_name,
                    "--network", network_mode,
                    "--memory", "256m",
                    "--cpus", "0.5",
                    "--read-only",
                    "--tmpfs", "/tmp:size=64m",
                    self.image,
                    "sleep", "3600",
                ],
                capture_output=True, text=True, check=True, timeout=60,
            )
        except subprocess.CalledProcessError as e:
            self._container_name = None
            raise SandboxError(f"Failed to start sandbox container: {e.stderr.strip()}") from e
        except subprocess.TimeoutExpired as e:
            self._container_name = None
            raise SandboxError("Timed out starting sandbox container") from e
        except FileNotFoundError as e:
            self._container_name = None
            raise SandboxError("Docker is not installed or not on PATH") from e

        self._ready = True
        logger.info("Sandbox ready")
        return True

    def run_exploit(self, exploit_code: str, timeout_seconds: int = 30) -> ExecutionResult:
        if not self._ready or not self._container_name:
            raise SandboxError("Sandbox not set up — call setup_environment first")

        logger.debug("Executing exploit in %s (timeout=%ds)", self._container_name, timeout_seconds)
        try:
            result = subprocess.run(
                [
                    "docker", "exec", self._container_name,
                    "python3", "-c", exploit_code,
                ],
                capture_output=True, text=True, timeout=timeout_seconds,
            )
            success = result.returncode == 0
            return ExecutionResult(
                success=success,
                exit_code=result.returncode,
                stdout=result.stdout[-4096:],
                stderr=result.stderr[-4096:],
            )
        except subprocess.TimeoutExpired:
            logger.warning("Exploit timed out after %ds in %s", timeout_seconds, self._container_name)
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Exploit timed out after {timeout_seconds}s",
            )
        except subprocess.CalledProcessError as e:
            raise SandboxError(f"Docker exec failed: {e.stderr.strip()}") from e

    def teardown(self) -> None:
        if not self._container_name:
            return

        logger.debug("Tearing down sandbox container %s", self._container_name)
        try:
            subprocess.run(
                ["docker", "rm", "-f", self._container_name],
                capture_output=True, text=True, check=True, timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error("Failed to remove container %s: %s", self._container_name, e)

        self._container_name = None
        self._ready = False
