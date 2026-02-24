"""
CloudFail v2.0 — Rich-based logger utility with debug and quiet modes
"""
from __future__ import annotations

import datetime
import traceback

from rich.console import Console

console = Console()


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def _quiet() -> bool:
    import cloudfail.config as _cfg
    return _cfg.QUIET_MODE


def _debug() -> bool:
    import cloudfail.config as _cfg
    return _cfg.DEBUG_MODE


def info(msg: str) -> None:
    if not _quiet():
        console.print(f"[dim][{_ts()}][/dim] [cyan]{msg}[/cyan]")


def success(msg: str) -> None:
    if not _quiet():
        console.print(f"[dim][{_ts()}][/dim] [bold green][FOUND][/bold green] {msg}")


def warning(msg: str) -> None:
    if not _quiet():
        console.print(f"[dim][{_ts()}][/dim] [bold yellow][WARN][/bold yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[dim][{_ts()}][/dim] [bold red][ERROR][/bold red] {msg}")


def debug(msg: str) -> None:
    if _debug():
        console.print(f"[dim][{_ts()}][/dim] [dim magenta][DEBUG][/dim magenta] [dim]{msg}[/dim]")


def debug_exc(exc: BaseException, context: str = "") -> None:
    """Print full traceback only in --debug mode."""
    if _debug():
        prefix = f"[{context}] " if context else ""
        console.print(
            f"[dim][{_ts()}][/dim] [dim magenta][DEBUG TRACE][/dim magenta] "
            f"[dim]{prefix}{type(exc).__name__}: {exc}[/dim]"
        )
        console.print_exception()


def section(title: str) -> None:
    if not _quiet():
        console.rule(f"[bold blue]{title}[/bold blue]")


def plain(msg: str) -> None:
    console.print(msg)
