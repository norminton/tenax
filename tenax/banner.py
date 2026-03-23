from __future__ import annotations

import shutil
import sys
import time


BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"


def _center_line(text: str, width: int) -> str:
    text_len = len(_strip_ansi(text))
    padding = max((width - text_len) // 2, 0)
    return " " * padding + text


def _strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _build_frames() -> list[list[str]]:
    """
    Builds a simple morph animation:
    TENACITY-LINUX -> TENAX
    """
    title_frames = [
        "TENACITY-LINUX",
        "TENACITY LINUX",
        "TENACITY  LINUX",
        "TENACITY   LINUX",
        "TENACITY    LINUX",
        "TENACIT      INUX",
        "TENACI        NUX",
        "TENAC          UX",
        "TENA            X",
        "TENAX",
    ]

    rendered: list[list[str]] = []

    for i, title in enumerate(title_frames):
        glow = CYAN if i < len(title_frames) - 2 else MAGENTA
        subtitle = f"{DIM}Comprehensive Linux Persistence Detection{RESET}"

        lines = [
            "",
            f"{glow}{BOLD}{title}{RESET}",
            "",
            subtitle,
            "",
        ]
        rendered.append(lines)

    return rendered


def show_startup_banner(duration: float = 5.0) -> None:
    """
    Plays a centered startup animation in the terminal.
    Safe to skip on non-interactive output.
    """
    if not sys.stdout.isatty():
        return

    frames = _build_frames()
    if not frames:
        return

    width = shutil.get_terminal_size((100, 30)).columns
    frame_delay = max(duration / len(frames), 0.08)

    try:
        for frame in frames:
            sys.stdout.write(CLEAR)
            for line in frame:
                sys.stdout.write(_center_line(line, width) + "\n")
            sys.stdout.flush()
            time.sleep(frame_delay)

        # brief hold on final TENAX frame
        time.sleep(0.35)
        sys.stdout.write(CLEAR)
        sys.stdout.flush()
    except KeyboardInterrupt:
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()