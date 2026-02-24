"""
CloudFail v2.0 — Rich-based logger utility
"""
from __future__ import annotations

import datetime
from typing import Optional

from rich.console import Console
from rich.text import Text

console = Console()


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    console.print(f"[dim][{_ts()}][/dim] [cyan]{msg}[/cyan]")


def success(msg: str) -> None:
    console.print(f"[dim][{_ts()}][/dim] [bold green][FOUND][/bold green] {msg}")


def warning(msg: str) -> None:
    console.print(f"[dim][{_ts()}][/dim] [bold yellow][WARN][/bold yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[dim][{_ts()}][/dim] [bold red][ERROR][/bold red] {msg}")


def section(title: str) -> None:
    console.rule(f"[bold blue]{title}[/bold blue]")


def plain(msg: str) -> None:
    console.print(msg)
