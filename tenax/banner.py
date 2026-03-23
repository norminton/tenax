from __future__ import annotations

import re
import shutil
import sys
import time

BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _center_line(text: str, width: int) -> str:
    visible_len = len(_strip_ansi(text))
    padding = max((width - visible_len) // 2, 0)
    return (" " * padding) + text


def _render_frame(lines: list[str], width: int) -> str:
    return "\n".join(_center_line(line, width) for line in lines)


def _build_frames() -> list[list[str]]:
    subtitle = f"{DIM}Comprehensive Linux Persistence Detection{RESET}"

    frames: list[list[str]] = []

    # Frame 1: TENACITY-LINUX full
    frames.append([
        "",
        f"{CYAN}{BOLD}████████╗███████╗███╗   ██╗ █████╗  ██████╗██╗████████╗██╗   ██╗      ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗{RESET}",
        f"{CYAN}{BOLD}╚══██╔══╝██╔════╝████╗  ██║██╔══██╗██╔════╝██║╚══██╔══╝╚██╗ ██╔╝      ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝{RESET}",
        f"{CYAN}{BOLD}   ██║   █████╗  ██╔██╗ ██║███████║██║     ██║   ██║    ╚████╔╝       ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ {RESET}",
        f"{CYAN}{BOLD}   ██║   ██╔══╝  ██║╚██╗██║██╔══██║██║     ██║   ██║     ╚██╔╝        ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ {RESET}",
        f"{CYAN}{BOLD}   ██║   ███████╗██║ ╚████║██║  ██║╚██████╗██║   ██║      ██║         ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗{RESET}",
        f"{CYAN}{BOLD}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚═╝   ╚═╝      ╚═╝         ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝{RESET}",
        "",
        subtitle,
        "",
    ])

    # Frame 2: compressed / transition
    frames.append([
        "",
        f"{CYAN}{BOLD}████████╗███████╗███╗   ██╗ █████╗ ██╗  ██╗{RESET}",
        f"{CYAN}{BOLD}╚══██╔══╝██╔════╝████╗  ██║██╔══██╗╚██╗██╔╝{RESET}",
        f"{CYAN}{BOLD}   ██║   █████╗  ██╔██╗ ██║███████║ ╚███╔╝ {RESET}",
        f"{CYAN}{BOLD}   ██║   ██╔══╝  ██║╚██╗██║██╔══██║ ██╔██╗ {RESET}",
        f"{CYAN}{BOLD}   ██║   ███████╗██║ ╚████║██║  ██║██╔╝ ██╗{RESET}",
        f"{CYAN}{BOLD}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝{RESET}",
        "",
        subtitle,
        "",
    ])

    # Frame 3: TENAX final
    frames.append([
        "",
        f"{MAGENTA}{BOLD}████████╗███████╗███╗   ██╗ █████╗ ██╗  ██╗{RESET}",
        f"{MAGENTA}{BOLD}╚══██╔══╝██╔════╝████╗  ██║██╔══██╗╚██╗██╔╝{RESET}",
        f"{MAGENTA}{BOLD}   ██║   █████╗  ██╔██╗ ██║███████║ ╚███╔╝ {RESET}",
        f"{MAGENTA}{BOLD}   ██║   ██╔══╝  ██║╚██╗██║██╔══██║ ██╔██╗ {RESET}",
        f"{MAGENTA}{BOLD}   ██║   ███████╗██║ ╚████║██║  ██║██╔╝ ██╗{RESET}",
        f"{MAGENTA}{BOLD}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝{RESET}",
        "",
        subtitle,
        "",
    ])

    return frames


def show_startup_banner(duration: float = 5.0) -> None:
    if not sys.stdout.isatty():
        return

    frames = _build_frames()
    width = shutil.get_terminal_size((140, 40)).columns

    # Heavier weighting toward the final TENAX frame
    frame_schedule = [0.40, 0.30, 0.30]
    total = sum(frame_schedule)

    try:
        for frame, ratio in zip(frames, frame_schedule):
            sys.stdout.write(CLEAR)
            sys.stdout.write(_render_frame(frame, width))
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(duration * (ratio / total))

        sys.stdout.write(CLEAR)
        sys.stdout.flush()
    except KeyboardInterrupt:
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()