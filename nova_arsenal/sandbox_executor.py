"""
Sandbox Executor - Executes commands inside the Kali Linux container.

Supports:
- Docker exec (primary)
- SSH (fallback)
- Direct subprocess (local/dev mode)
"""

import asyncio
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    working_dir: str = "/"

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """Combined output."""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR]\n{self.stderr}")
        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "working_dir": self.working_dir,
        }


class SandboxExecutor:
    """
    Executes commands inside the Kali Linux sandbox.
    
    Modes:
    - docker: Uses docker exec to run in nova-sandbox container
    - ssh: Uses SSH to connect to the sandbox
    - local: Runs directly on the host (dev/testing mode)
    """

    def __init__(
        self,
        mode: str = "docker",
        container_name: str = "nova-sandbox",
        ssh_host: str = "",
        ssh_port: int = 22,
        ssh_user: str = "agent",
        ssh_key: str = "",
        timeout: int = 120,
        max_output: int = 50000,
    ) -> None:
        self.mode = mode
        self.container_name = container_name
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.timeout = timeout
        self.max_output = max_output
        self._history: list[ExecResult] = []

    async def execute(
        self,
        command: str,
        working_dir: str = "/tmp",
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecResult:
        """Execute a command in the sandbox."""
        timeout = timeout or self.timeout
        logger.info(f"[SANDBOX] Executing: {command}")

        try:
            if self.mode == "docker":
                result = await self._execute_docker(command, working_dir, timeout, env)
            elif self.mode == "ssh":
                result = await self._execute_ssh(command, working_dir, timeout, env)
            elif self.mode == "local":
                result = await self._execute_local(command, working_dir, timeout, env)
            else:
                result = ExecResult(
                    command=command,
                    stdout="",
                    stderr=f"Unknown execution mode: {self.mode}",
                    exit_code=1,
                )
        except asyncio.TimeoutError:
            result = ExecResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                timed_out=True,
                working_dir=working_dir,
            )
        except Exception as e:
            result = ExecResult(
                command=command,
                stdout="",
                stderr=f"Execution error: {e}",
                exit_code=-1,
                working_dir=working_dir,
            )

        # Truncate large output
        if len(result.stdout) > self.max_output:
            result.stdout = result.stdout[:self.max_output] + "\n... [TRUNCATED]"
        if len(result.stderr) > self.max_output:
            result.stderr = result.stderr[:self.max_output] + "\n... [TRUNCATED]"

        self._history.append(result)
        return result

    async def execute_script(
        self,
        script: str,
        filename: str = "script.sh",
        working_dir: str = "/tmp",
        timeout: Optional[int] = None,
    ) -> ExecResult:
        """Write a script to the sandbox and execute it."""
        # Write script to temp file and copy it in
        if self.mode == "docker":
            # Create script inside container
            escaped = script.replace("'", "'\\''")
            cmd = f"bash -c '{escaped}'"
            return await self.execute(cmd, working_dir, timeout)
        elif self.mode == "local":
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f"_{filename}", delete=False
            ) as f:
                f.write(script)
                f.flush()
                try:
                    result = await self.execute_local(
                        f"bash {f.name}", working_dir, timeout
                    )
                finally:
                    os.unlink(f.name)
            return result
        else:
            return await self.execute(f"bash -c '{script}'", working_dir, timeout)

    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
    ) -> bool:
        """Upload a file to the sandbox."""
        try:
            if self.mode == "docker":
                proc = await asyncio.create_subprocess_exec(
                    "docker", "cp", local_path,
                    f"{self.container_name}:{remote_path}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                return proc.returncode == 0
            elif self.mode == "local":
                import shutil
                shutil.copy2(local_path, remote_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    async def download_file(
        self,
        remote_path: str,
        local_path: str,
    ) -> bool:
        """Download a file from the sandbox."""
        try:
            if self.mode == "docker":
                proc = await asyncio.create_subprocess_exec(
                    "docker", "cp",
                    f"{self.container_name}:{remote_path}", local_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                return proc.returncode == 0
            elif self.mode == "local":
                import shutil
                shutil.copy2(remote_path, local_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    async def file_exists(self, path: str) -> bool:
        """Check if a file exists in the sandbox."""
        result = await self.execute(f"test -f {path} && echo EXISTS || echo MISSING")
        return "EXISTS" in result.stdout

    async def directory_exists(self, path: str) -> bool:
        """Check if a directory exists in the sandbox."""
        result = await self.execute(f"test -d {path} && echo EXISTS || echo MISSING")
        return "EXISTS" in result.stdout

    async def list_directory(self, path: str = "/tmp") -> str:
        """List directory contents."""
        result = await self.execute(f"ls -la {path}")
        return result.stdout

    async def check_tool_installed(self, tool: str) -> bool:
        """Check if a tool is installed in the sandbox."""
        result = await self.execute(f"which {tool} 2>/dev/null || echo NOT_FOUND")
        return "NOT_FOUND" not in result.stdout

    def get_history(self) -> list[ExecResult]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()

    # ── Internal execution methods ──────────────────────────────────────────

    async def _execute_docker(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecResult:
        """Execute via docker exec."""
        cmd_args = ["docker", "exec", "-w", working_dir]

        if env:
            for k, v in env.items():
                cmd_args.extend(["-e", f"{k}={v}"])

        cmd_args.extend([self.container_name, "bash", "-c", command])

        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        return ExecResult(
            command=command,
            stdout=stdout.decode(errors="replace").strip(),
            stderr=stderr.decode(errors="replace").strip(),
            exit_code=proc.returncode or 0,
            working_dir=working_dir,
        )

    async def _execute_ssh(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecResult:
        """Execute via SSH."""
        ssh_args = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(self.ssh_port),
        ]

        if self.ssh_key:
            ssh_args.extend(["-i", self.ssh_key])

        ssh_args.append(f"{self.ssh_user}@{self.ssh_host}")
        ssh_args.append(f"cd {working_dir} && {command}")

        proc = await asyncio.create_subprocess_exec(
            *ssh_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        return ExecResult(
            command=command,
            stdout=stdout.decode(errors="replace").strip(),
            stderr=stderr.decode(errors="replace").strip(),
            exit_code=proc.returncode or 0,
            working_dir=working_dir,
        )

    async def _execute_local(
        self,
        command: str,
        working_dir: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecResult:
        """Execute locally via subprocess."""
        full_env = dict(os.environ)
        if env:
            full_env.update(env)

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
            env=full_env,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )

        return ExecResult(
            command=command,
            stdout=stdout.decode(errors="replace").strip(),
            stderr=stderr.decode(errors="replace").strip(),
            exit_code=proc.returncode or 0,
            working_dir=working_dir,
        )


def create_executor(
    mode: Optional[str] = None,
    container_name: Optional[str] = None,
) -> SandboxExecutor:
    """Factory to create a SandboxExecutor from environment."""
    mode = mode or os.getenv("NOVA_SANDBOX_MODE", "docker")
    container_name = container_name or os.getenv("NOVA_SANDBOX_CONTAINER", "nova-sandbox")

    ssh_host = os.getenv("NOVA_SSH_HOST", "")
    ssh_port = int(os.getenv("NOVA_SSH_PORT", "22"))
    ssh_user = os.getenv("NOVA_SSH_USER", "agent")
    ssh_key = os.getenv("NOVA_SSH_KEY", "")

    return SandboxExecutor(
        mode=mode,
        container_name=container_name,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
    )
