"""
system_collector.py — System resource telemetry for Cyber Sentinel XDR endpoint agent.

Collects CPU, memory, disk usage and the top-10 CPU-consuming processes.
All psutil calls are wrapped so a single failure does not abort the rest of
the collection.
"""

import logging
from typing import Any

import psutil

logger = logging.getLogger(__name__)


async def collect_system() -> dict[str, Any]:
    """
    Return a system resource snapshot.

    The function is declared async for uniform awaiting in the telemetry loop.
    psutil calls are synchronous; cpu_percent uses a 0.5 s sampling interval
    which is the minimum that gives a meaningful reading without blocking long.

    Returns:
        {
            "cpu_percent": float,
            "memory_percent": float,
            "memory_used_mb": float,
            "disk_percent": float,
            "process_count": int,
            "processes": [{"pid", "name", "cpu_percent", "memory_mb"}, ...],
        }
    """
    # --- CPU ---
    cpu_percent = 0.0
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
    except Exception as exc:
        logger.warning("cpu_percent() failed: %s", exc)

    # --- Memory ---
    memory_percent = 0.0
    memory_used_mb = 0.0
    try:
        vm = psutil.virtual_memory()
        memory_percent = vm.percent
        memory_used_mb = round(vm.used / 1_048_576, 1)
    except Exception as exc:
        logger.warning("virtual_memory() failed: %s", exc)

    # --- Disk (root / system drive) ---
    disk_percent = 0.0
    try:
        # On Windows psutil.disk_usage('C:\\') is always valid;
        # on Linux '/' is used.  We try both gracefully.
        import sys
        disk_root = "C:\\" if sys.platform == "win32" else "/"
        disk_percent = psutil.disk_usage(disk_root).percent
    except Exception as exc:
        logger.warning("disk_usage() failed: %s", exc)

    # --- Process list ---
    process_count = 0
    processes: list[dict[str, Any]] = []
    try:
        all_pids = psutil.pids()
        process_count = len(all_pids)
    except Exception as exc:
        logger.warning("pids() failed: %s", exc)

    try:
        raw_procs: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                mem_mb = 0.0
                if info.get("memory_info") is not None:
                    mem_mb = round(info["memory_info"].rss / 1_048_576, 2)
                raw_procs.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name") or "",
                        "cpu_percent": info.get("cpu_percent") or 0.0,
                        "memory_mb": mem_mb,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process disappeared or we lack permission — skip silently
                continue
            except Exception as exc:
                logger.debug("Skipping process entry: %s", exc)
                continue

        # Top 10 by CPU usage
        raw_procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
        processes = raw_procs[:10]

    except Exception as exc:
        logger.warning("process_iter() failed: %s", exc)

    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "memory_used_mb": memory_used_mb,
        "disk_percent": disk_percent,
        "process_count": process_count,
        "processes": processes,
    }
