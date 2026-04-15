import multiprocessing
import os
import signal
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from core.collector import run_collector
from core.loader import load_all_modules
from core.orchestrator import ShadowOrchestrator
from core.reporter import DailyReporter
from dashboard.main import run_dashboard_server


def _read_config(path: str = "config.yaml") -> dict[str, Any]:
    config_file = Path(path)
    defaults: dict[str, Any] = {
        "telemetry": {"port": 5555},
        "modules": {"directory": "./modules"},
        "orchestrator": {"join_interval_seconds": 2},
        "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 8055},
    }

    if not config_file.exists():
        return defaults

    try:
        import yaml  # type: ignore

        raw = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(value, dict) and isinstance(defaults.get(key), dict):
                    defaults[key].update(value)
                else:
                    defaults[key] = value
    except Exception as exc:
        print(f"[orchestrator] Config load warning: {exc}")

    return defaults


def run_scaled_runtime(include_modules: bool = True, include_dashboard: bool = True) -> None:
    config = _read_config()
    telemetry_port = int(config.get("telemetry", {}).get("port", 5555))
    module_dir = str(config.get("modules", {}).get("directory", "./modules"))
    join_interval = int(config.get("orchestrator", {}).get("join_interval_seconds", 2))
    dashboard_cfg = config.get("dashboard", {})
    dashboard_enabled = bool(dashboard_cfg.get("enabled", True)) and include_dashboard
    dashboard_host = str(dashboard_cfg.get("host", "127.0.0.1"))
    dashboard_port = int(dashboard_cfg.get("port", 8000))

    collector = multiprocessing.Process(target=run_collector, args=(telemetry_port,), name="collector")
    collector.start()

    modules = load_all_modules(module_dir=module_dir) if include_modules else []
    dashboard: multiprocessing.Process | None = None
    if dashboard_enabled:
        dashboard = multiprocessing.Process(
            target=run_dashboard_server,
            args=(dashboard_host, dashboard_port),
            name="dashboard",
        )
        dashboard.start()

    print(
        "[*] Orchestrator started: collector + "
        f"{len(modules)} module(s)"
        f"{(' + dashboard' if dashboard else '')}"
    )

    scheduler_stop = threading.Event()

    def _next_daily_run(target_hhmm: str) -> datetime:
        now = datetime.now()
        hour = 0
        minute = 0
        try:
            hour_str, minute_str = target_hhmm.split(":", maxsplit=1)
            hour = max(0, min(23, int(hour_str)))
            minute = max(0, min(59, int(minute_str)))
        except Exception:
            pass

        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate = candidate + timedelta(days=1)
        return candidate

    def _maintenance_scheduler() -> None:
        daily_time = os.getenv("SHADOW_DAILY_REPORT_TIME", "00:00")
        next_run = _next_daily_run(daily_time)
        print(f"[*] Maintenance scheduler active. Next daily report at {next_run:%Y-%m-%d %H:%M}")

        while not scheduler_stop.is_set():
            now = datetime.now()
            if now >= next_run:
                try:
                    stats = DailyReporter().dispatch_reports()
                    print(
                        "[*] Daily reports dispatched: "
                        f"businesses={stats.get('businesses_reported', 0)}, "
                        f"emails={stats.get('emails_sent', 0)}"
                    )
                except Exception as exc:
                    print(f"[scheduler] daily report cycle failed: {exc}")
                next_run = _next_daily_run(daily_time)
            scheduler_stop.wait(timeout=30)

    scheduler_thread = threading.Thread(target=_maintenance_scheduler, name="daily-maintenance", daemon=True)
    scheduler_thread.start()

    try:
        while True:
            if not collector.is_alive():
                print("[!] Collector stopped. Terminating modules.")
                break
            if dashboard and not dashboard.is_alive():
                print("[!] Dashboard server stopped. Continuing without dashboard.")
                dashboard = None
            
            # Watchdog: detect crashed modules
            for proc in modules:
                if not proc.is_alive():
                    print(f"[!] Module {proc.name} crashed (watchdog detected). Use orchestrator for auto-restart.")
            
            time.sleep(max(1, join_interval))
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested by operator")
    finally:
        scheduler_stop.set()
        scheduler_thread.join(timeout=2)

        for proc in modules:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=3)

        if dashboard and dashboard.is_alive():
            dashboard.terminate()
            dashboard.join(timeout=3)

        if collector.is_alive():
            collector.terminate()
            collector.join(timeout=3)


def main() -> None:
    manager = ShadowOrchestrator()
    print("--- SHADOW-TOOLZ ORCHESTRATOR v1.0 ---")
    shutting_down = False

    def _shutdown_handler(_sig: int, _frame: object) -> None:
        nonlocal shutting_down
        if not shutting_down:
            shutting_down = True
            manager.shutdown(exit_process=True)

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    try:
        while True:
            try:
                parts = input("shadow > ").strip().split()
            except EOFError:
                shutting_down = True
                manager.shutdown(exit_process=True)

            if not parts:
                continue

            action = parts[0].lower()

            if action == "list":
                print(f"Available: {manager._get_module_list()}")
                print(f"Running: {list(manager.status_snapshot().keys())}")
            elif action == "start" and len(parts) > 1:
                manager.start_module(parts[1])
            elif action == "stop" and len(parts) > 1:
                manager.stop_module(parts[1])
            elif action == "start-all":
                manager.start_all()
            elif action == "stop-all":
                manager.stop_all()
            elif action in {"status", "ps"}:
                manager.monitor_and_revive()  # Check for crashed modules
                status = manager.status_snapshot()
                if not status:
                    print("[*] No active module processes.")
                else:
                    # Enhanced status with table format
                    print(f"{'MODULE':<20} | {'PID':<8} | {'STATUS':<10}")
                    print("-" * 42)
                    for name, meta in status.items():
                        status_str = "🟢 ALIVE" if meta["alive"] else "🔴 CRASHED"
                        print(f"{name:<20} | {str(meta['pid']):<8} | {status_str:<10}")
            elif action == "purge-logs":
                confirm = input("[!] Are you sure you want to clear all audit logs? (y/n): ").strip().lower()
                if confirm == 'y':
                    # Clear the master log
                    audit_path = Path("data/master_audit.log")
                    audit_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(audit_path, "w", encoding="utf-8") as f:
                        f.write(f"--- LOG PURGED BY OPERATOR AT {time.ctime()} ---\n")
                    
                    # Clear module-specific logs if they exist
                    for module in manager._get_module_list():
                        log_path = Path(f"modules/{module}/{module}_local.log")
                        if log_path.exists():
                            log_path.write_text("", encoding="utf-8")
                    
                    print("[+] All logs cleared. Forensic state reset.")
                else:
                    print("[*] Purge cancelled.")
            elif action == "exit":
                shutting_down = True
                manager.shutdown(exit_process=True)
            else:
                print("Commands: list, start [name], stop [name], start-all, stop-all, status, purge-logs, exit")
    finally:
        if not shutting_down:
            manager.shutdown(exit_process=False)


def main_lite() -> None:
    run_scaled_runtime(include_modules=False, include_dashboard=True)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
