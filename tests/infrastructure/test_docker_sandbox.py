# tests/infrastructure/test_docker_sandbox.py

from unittest.mock import patch, MagicMock
import subprocess

import pytest
from aegis.infrastructure.adapters.docker_sandbox import DockerSandbox
from aegis.domain.exceptions import SandboxError


class TestDockerSandboxSetup:

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_setup_creates_container(self, mock_run):
        sandbox = DockerSandbox()
        result = sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")

        assert result is True
        assert sandbox._container_name is not None
        assert sandbox._ready is True

        call_args = mock_run.call_args[0][0]
        assert call_args[0:3] == ["docker", "run", "-d"]
        assert "--network" in call_args
        assert "none" in call_args
        assert "--read-only" in call_args

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_setup_with_network_enabled(self, mock_run):
        sandbox = DockerSandbox(network=True)
        sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")

        call_args = mock_run.call_args[0][0]
        network_idx = call_args.index("--network")
        assert call_args[network_idx + 1] == "bridge"

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_setup_failure_raises_sandbox_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker", stderr="image not found")
        sandbox = DockerSandbox()

        with pytest.raises(SandboxError, match="Failed to start"):
            sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")

        assert sandbox._container_name is None
        assert sandbox._ready is False

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_setup_timeout_raises_sandbox_error(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 60)
        sandbox = DockerSandbox()

        with pytest.raises(SandboxError, match="Timed out"):
            sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_setup_docker_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        sandbox = DockerSandbox()

        with pytest.raises(SandboxError, match="not installed"):
            sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")


class TestDockerSandboxRunExploit:

    def _setup_sandbox(self, mock_run):
        sandbox = DockerSandbox()
        sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")
        mock_run.reset_mock()
        return sandbox

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_run_exploit_success(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        mock_run.return_value = MagicMock(returncode=0, stdout="pwned", stderr="")

        result = sandbox.run_exploit("print('pwned')")

        assert result.success is True
        assert result.exit_code == 0
        assert result.stdout == "pwned"
        call_args = mock_run.call_args[0][0]
        assert "docker" in call_args
        assert "exec" in call_args

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_run_exploit_failure(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Traceback...")

        result = sandbox.run_exploit("raise Exception()")

        assert result.success is False
        assert result.exit_code == 1

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_run_exploit_timeout(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)

        result = sandbox.run_exploit("import time; time.sleep(999)", timeout_seconds=30)

        assert result.success is False
        assert result.exit_code == -1
        assert "timed out" in result.stderr

    def test_run_exploit_without_setup_raises(self):
        sandbox = DockerSandbox()

        with pytest.raises(SandboxError, match="not set up"):
            sandbox.run_exploit("print('hello')")

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_run_exploit_truncates_large_output(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        large_output = "x" * 10000
        mock_run.return_value = MagicMock(returncode=0, stdout=large_output, stderr="")

        result = sandbox.run_exploit("print('x' * 10000)")

        assert len(result.stdout) == 4096


class TestDockerSandboxTeardown:

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_teardown_removes_container(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        container_name = sandbox._container_name

        sandbox.teardown()

        call_args = mock_run.call_args[0][0]
        assert call_args == ["docker", "rm", "-f", container_name]
        assert sandbox._container_name is None
        assert sandbox._ready is False

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_teardown_without_setup_is_noop(self, mock_run):
        sandbox = DockerSandbox()
        sandbox.teardown()
        mock_run.assert_not_called()

    @patch("aegis.infrastructure.adapters.docker_sandbox.subprocess.run")
    def test_teardown_failure_does_not_raise(self, mock_run):
        sandbox = self._setup_sandbox(mock_run)
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker", stderr="no such container")

        sandbox.teardown()

        assert sandbox._container_name is None
        assert sandbox._ready is False

    def _setup_sandbox(self, mock_run):
        sandbox = DockerSandbox()
        sandbox.setup_environment(repo_url="https://github.com/fake/repo", commit_hash="HEAD")
        mock_run.reset_mock()
        return sandbox
