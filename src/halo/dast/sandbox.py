"""DAST Sandbox Manager: Container lifecycle, readiness polling, and safe mode guardrails."""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Known local hostnames
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "testapp", "test"}

# Synthetic test identities permitted to perform mutations in Safe Mode
SYNTHETIC_IDENTITIES = {
    "halo_user_a",
    "halo_user_b",
    "halo_admin",
    "user_a",
    "user_b",
}


class SafeModeViolationError(Exception):
    """Raised when an active DAST probe violates Safe Mode isolation guardrails."""


class SandboxManager:
    """Manages Docker/Podman container lifecycle, readiness checking, and safe mode guardrails."""

    def __init__(
        self,
        runtime: str | None = None,
        safe_mode: bool = True,
        default_port: int = 8000,
    ) -> None:
        self.safe_mode = safe_mode
        self.default_port = default_port
        self.container_id: str | None = None
        self.container_url: str | None = None
        self.runtime = runtime or self._detect_runtime()
        self._is_running = False

    def _detect_runtime(self) -> str:
        """Detect container runtime favoring podman (rootless default) or docker."""
        if shutil.which("podman"):
            return "podman"
        if shutil.which("docker"):
            return "docker"
        return "docker"

    @property
    def is_running(self) -> bool:
        """Indicates whether a sandbox container is currently running."""
        return self._is_running and self.container_id is not None

    @property
    def status(self) -> str:
        """Current operational status of the sandbox container."""
        if self.is_running:
            return "running"
        if self.container_id:
            return "stopped"
        return "idle"

    def is_remote_target(self, url: str) -> bool:
        """Check if target URL points to an external/remote host rather than local sandbox."""
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            if not hostname:
                return False
            return hostname not in LOCAL_HOSTS
        except ValueError:
            return True

    def check_safe_mode_guardrails(
        self,
        target_url: str,
        method: str,
        path: str = "",
        identity: str | None = None,
        resource_owner: str | None = None,
    ) -> tuple[bool, str]:
        """Validate whether a probe mutation is permitted under Safe Mode constraints."""
        if not self.safe_mode:
            return True, "Safe mode disabled"

        # Local sandbox targets are fully permitted
        if not self.is_remote_target(target_url):
            return True, "Local target is unrestricted"

        upper_method = method.upper()

        # Read-only operations are safe
        if upper_method in ("GET", "HEAD", "OPTIONS"):
            return True, "Safe read-only operation permitted"

        # In Safe Mode against remote targets, mutations must strictly use synthetic identities
        clean_identity = (identity or "").lower()
        if not any(clean_identity.startswith(syn) or clean_identity == syn for syn in SYNTHETIC_IDENTITIES):
            return False, (
                f"Safe Mode Guardrail: Mutation via {upper_method} on remote target {target_url} "
                f"is blocked for non-synthetic identity '{identity}'. Only synthetic personas permitted."
            )

        # Destructive operations (DELETE or mutating foreign entities)
        if upper_method == "DELETE" and (not resource_owner or resource_owner.lower() != clean_identity):
            return False, (
                f"Safe Mode Guardrail: Destructive DELETE operation on remote entity at {path} "
                f"is blocked against foreign resource owner '{resource_owner}'."
            )

        if upper_method in ("PUT", "PATCH", "POST") and (resource_owner and resource_owner.lower() not in SYNTHETIC_IDENTITIES):
            return False, (
                f"Safe Mode Guardrail: Destructive mutation ({upper_method}) on foreign entity "
                f"owned by '{resource_owner}' is blocked."
            )

        return True, "Operation permitted under Safe Mode"

    def enforce_safe_mode(
        self,
        target_url: str,
        method: str,
        path: str = "",
        identity: str | None = None,
        resource_owner: str | None = None,
    ) -> None:
        """Enforce safe mode guardrails, raising SafeModeViolationError if blocked."""
        allowed, reason = self.check_safe_mode_guardrails(
            target_url=target_url,
            method=method,
            path=path,
            identity=identity,
            resource_owner=resource_owner,
        )
        if not allowed:
            logger.error("Safe mode violation blocked: %s", reason)
            raise SafeModeViolationError(reason)

    def boot_sandbox(
        self,
        repo_path: str | Path,
        dockerfile_path: str | Path | None = None,
        port: int | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> str:
        """Boot target application in rootless container without host Docker socket access."""
        repo_dir = Path(repo_path).resolve()
        app_port = port or self.default_port

        if not shutil.which(self.runtime):
            raise RuntimeError(f"Container runtime '{self.runtime}' not available in PATH.")

        # Construct image tag
        image_tag = f"halo-sandbox-{repo_dir.name.lower()}:{int(time.time())}"

        # 1. Build image
        build_cmd = [self.runtime, "build", "-t", image_tag]
        if dockerfile_path:
            build_cmd.extend(["-f", str(dockerfile_path)])
        build_cmd.append(str(repo_dir))

        logger.info("Building sandbox container: %s", " ".join(build_cmd))
        build_proc = subprocess.run(build_cmd, capture_output=True, text=True, check=False)
        if build_proc.returncode != 0:
            raise RuntimeError(f"Sandbox build failed: {build_proc.stderr}")

        # 2. Run container in rootless isolated network
        run_cmd = [
            self.runtime,
            "run",
            "-d",
            "--rm",
            "--network",
            "bridge",
            "--security-opt",
            "no-new-privileges",
            "-p",
            f"{app_port}:{app_port}",
        ]

        if env_vars:
            for k, v in env_vars.items():
                run_cmd.extend(["-e", f"{k}={v}"])

        run_cmd.append(image_tag)

        logger.info("Starting sandbox container: %s", " ".join(run_cmd))
        run_proc = subprocess.run(run_cmd, capture_output=True, text=True, check=False)
        if run_proc.returncode != 0:
            raise RuntimeError(f"Sandbox run failed: {run_proc.stderr}")

        self.container_id = run_proc.stdout.strip()[:12]
        self.container_url = f"http://127.0.0.1:{app_port}"
        self._is_running = True
        logger.info("Sandbox container started: %s on %s", self.container_id, self.container_url)
        return self.container_url

    def wait_for_readiness(
        self,
        url: str,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
        readiness_path: str = "/health",
    ) -> bool:
        """Poll TCP connect and HTTP readiness endpoint with timeout."""
        start_time = time.time()
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        while time.time() - start_time < timeout:
            # 1. TCP Connect probe
            tcp_ok = self._check_tcp(host, port)
            if tcp_ok:
                # 2. HTTP readiness endpoint probe
                http_ok = self._check_endpoint(url, readiness_path)
                if http_ok:
                    return True
            else:
                if self._check_endpoint(url, readiness_path):
                    return True

            time.sleep(poll_interval)

        logger.warning("Readiness timeout exceeded (%ss) for %s", timeout, url)
        return False

    def _check_tcp(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Attempt TCP connection to host:port."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            return False

    def _check_endpoint(self, url: str, readiness_path: str = "/health") -> bool:
        """Poll HTTP readiness endpoint; accepts any responsive 2xx, 3xx, or 404."""
        probe_url = f"{url.rstrip('/')}{readiness_path}"
        try:
            resp = httpx.get(probe_url, timeout=2.0)
            if resp.status_code < 500:
                return True
        except httpx.HTTPError:
            try:
                base_resp = httpx.get(url, timeout=2.0)
                if base_resp.status_code < 500:
                    return True
            except httpx.HTTPError as err:
                logger.debug("Readiness probe failed on base url %s: %s", url, err)
        return False

    def health_check(self, url: str | None = None) -> bool:
        """Perform instant health check on running sandbox."""
        target = url or self.container_url
        if not target:
            return False
        return self._check_endpoint(target)

    def stop(self, container_id: str | None = None) -> bool:
        """Stop and remove sandbox container."""
        cid = container_id or self.container_id
        if not cid:
            return True

        if not shutil.which(self.runtime):
            self._is_running = False
            return True

        stop_cmd = [self.runtime, "stop", cid]
        proc = subprocess.run(stop_cmd, capture_output=True, text=True, check=False)
        self._is_running = False
        self.container_id = None
        self.container_url = None
        return proc.returncode == 0

    def cleanup(self) -> None:
        """Clean up resources on shutdown."""
        if self.is_running:
            self.stop()
