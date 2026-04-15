from __future__ import annotations

import importlib
import logging
import multiprocessing
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


MASTER_AUDIT_LOG = Path("data/master_audit.log")
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 5  # Keep .1 through .5


class _ModuleNameFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "module_name"):
            record.module_name = "orchestrator"
        return super().format(record)


class _StreamToLogger:
    def __init__(self, logger: logging.Logger | logging.LoggerAdapter, level: int) -> None:
        self.logger = logger
        self.level = level

    def write(self, message: str) -> None:
        for line in message.rstrip().splitlines():
            if line.strip():
                self.logger.log(self.level, line)

    def flush(self) -> None:
        return


def _configure_master_logger() -> logging.Logger:
    MASTER_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("shadow.master")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = _ModuleNameFormatter("%(asctime)s [%(levelname)s] [%(module_name)s] %(message)s")

    # Use RotatingFileHandler for automatic log rotation
    file_handler = RotatingFileHandler(
        MASTER_AUDIT_LOG, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


def _run_module_with_logging(name: str) -> None:
    logger = _configure_master_logger()
    mod_logger = logging.LoggerAdapter(logger, {"module_name": name})
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = _StreamToLogger(mod_logger, logging.INFO)
    sys.stderr = _StreamToLogger(mod_logger, logging.ERROR)

    try:
        module_spec = importlib.import_module(f"modules.{name}.main")
        mod_logger.info("Module process bootstrap complete")
        module_spec.run()
    except Exception:
        mod_logger.exception("Module crash")
        raise
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr


class ShadowOrchestrator:
    def __init__(self, module_path: str = "modules") -> None:
        self.module_path = Path(module_path)
        self.active_modules: dict[str, multiprocessing.Process] = {}
        self.logger = _configure_master_logger()
        self.audit = logging.LoggerAdapter(self.logger, {"module_name": "orchestrator"})

    def _get_module_list(self) -> list[str]:
        if not self.module_path.exists():
            return []
        return [
            entry.name
            for entry in sorted(self.module_path.iterdir())
            if entry.is_dir() and not entry.name.startswith("__")
        ]

    def _cleanup_dead_modules(self) -> None:
        stale = [name for name, proc in self.active_modules.items() if not proc.is_alive()]
        for name in stale:
            process = self.active_modules.pop(name, None)
            if process is not None and process.exitcode not in (0, None):
                self.audit.error("Module exited unexpectedly", extra={"module_name": name})

    def start_module(self, name: str) -> None:
        self._cleanup_dead_modules()
        if name in self.active_modules:
            print(f"[*] {name} is already active.")
            return

        if name not in self._get_module_list():
            print(f"[!] Unknown module: {name}")
            self.audit.warning("Attempted to start unknown module", extra={"module_name": name})
            return

        try:
            process = multiprocessing.Process(target=_run_module_with_logging, args=(name,), name=f"mod-{name}")
            process.start()
            self.active_modules[name] = process
            self.audit.info("Module started", extra={"module_name": name})
            print(f"[+] Launched {name} (PID: {process.pid})")
        except Exception as exc:
            self.audit.exception("Failed to start module", extra={"module_name": name})
            print(f"[!] Failed to launch {name}: {exc}")

    def stop_module(self, name: str) -> None:
        self._cleanup_dead_modules()
        process = self.active_modules.get(name)
        if not process:
            print(f"[!] {name} is not running.")
            return

        process.terminate()
        process.join(timeout=3)
        self.active_modules.pop(name, None)
        self.audit.info("Module terminated", extra={"module_name": name})
        print(f"[-] Terminated {name}.")

    def start_all(self) -> None:
        for name in self._get_module_list():
            self.start_module(name)

    def stop_all(self) -> None:
        self._cleanup_dead_modules()
        for name in list(self.active_modules.keys()):
            self.stop_module(name)

    def status_snapshot(self) -> dict[str, dict[str, int | bool | None]]:
        self._cleanup_dead_modules()
        return {
            name: {
                "pid": proc.pid,
                "alive": proc.is_alive(),
                "exitcode": proc.exitcode,
            }
            for name, proc in self.active_modules.items()
        }

    def monitor_and_revive(self) -> None:
        """Check for crashed modules and automatically restart them (watchdog)."""
        self._cleanup_dead_modules()
        for name, process in list(self.active_modules.items()):
            if not process.is_alive():
                self.audit.warning("Module crash detected; attempting auto-restart", extra={"module_name": name})
                del self.active_modules[name]
                self.start_module(name)

    def shutdown(self, exit_process: bool = False) -> None:
        print("\\n[*] Shutting down all SHADOW-TOOLZ services...")
        self.audit.info("Shutdown requested")
        self.stop_all()
        if exit_process:
            raise SystemExit(0)
