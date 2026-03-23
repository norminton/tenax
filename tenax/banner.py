from __future__ import annotations

import re
import shutil
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
CLEAR = "\033[2J\033[H"


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _center_line(text: str, width: int) -> str:
    visible = len(_strip_ansi(text))
    pad = max((width - visible) // 2, 0)
    return (" " * pad) + text


def _render(lines: list[str], width: int) -> str:
    return "\n".join(_center_line(line, width) for line in lines)


def _frame_tenacity() -> list[str]:
    return [
        "",
        "",
        "",
        f"{CYAN}{BOLD}Tenacity in Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_compress_1() -> list[str]:
    return [
        "",
        "",
        "",
        f"{CYAN}{BOLD}Tenacity   Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_compress_2() -> list[str]:
    return [
        "",
        "",
        "",
        f"{CYAN}{BOLD}Tenaci   Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_compress_3() -> list[str]:
    return [
        "",
        "",
        "",
        f"{MAGENTA}{BOLD}Tena   x{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_tenax_big() -> list[str]:
    return [
        "",
        f"{MAGENTA}{BOLD}████████╗███████╗███╗   ██╗ █████╗ ██╗  ██╗{RESET}",
        f"{MAGENTA}{BOLD}╚══██╔══╝██╔════╝████╗  ██║██╔══██╗╚██╗██╔╝{RESET}",
        f"{MAGENTA}{BOLD}   ██║   █████╗  ██╔██╗ ██║███████║ ╚███╔╝ {RESET}",
        f"{MAGENTA}{BOLD}   ██║   ██╔══╝  ██║╚██╗██║██╔══██║ ██╔██╗ {RESET}",
        f"{MAGENTA}{BOLD}   ██║   ███████╗██║ ╚████║██║  ██║██╔╝ ██╗{RESET}",
        f"{MAGENTA}{BOLD}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def show_startup_banner(duration: float = 5.0) -> None:
    if not sys.stdout.isatty():
        return

    width = shutil.get_terminal_size((140, 40)).columns

    frames = [
        (_frame_tenacity(), 1.2),
        (_frame_compress_1(), 0.9),
        (_frame_compress_2(), 0.9),
        (_frame_compress_3(), 0.8),
        (_frame_tenax_big(), 1.2),
    ]

    total = sum(weight for _, weight in frames)
    scale = duration / total if total else 1.0

    try:
        for lines, weight in frames:
            sys.stdout.write(CLEAR)
            sys.stdout.write(_render(lines, width))
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(weight * scale)

        # Hold final TENAX for a moment
        time.sleep(0.5)

        sys.stdout.write(CLEAR)
        sys.stdout.flush()

    except KeyboardInterrupt:
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()