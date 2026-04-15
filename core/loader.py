import importlib
import multiprocessing
from pathlib import Path


def start_module(module_name: str) -> None:
    try:
        mod = importlib.import_module(f"modules.{module_name}.main")
        mod.run()
    except Exception as exc:
        print(f"[!] Critical failure in {module_name}: {exc}")


def load_all_modules(module_dir: str = "./modules") -> list[multiprocessing.Process]:
    processes: list[multiprocessing.Process] = []
    path = Path(module_dir)
    if not path.exists():
        return processes

    for entry in sorted(path.iterdir()):
        if entry.is_dir() and not entry.name.startswith("__"):
            process = multiprocessing.Process(target=start_module, args=(entry.name,), name=f"mod-{entry.name}")
            process.start()
            processes.append(process)
    return processes
