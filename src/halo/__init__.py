from __future__ import annotations

import os
from pathlib import Path

__version__ = "0.1.0"


def load_env_files() -> None:
    """Load key-value pairs from .env and ~/.halo/.env into os.environ if not already set."""
    candidates = [
        Path.cwd() / ".env",
        Path.home() / ".halo" / ".env",
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass


load_env_files()

