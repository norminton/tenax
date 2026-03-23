from __future__ import annotations

import re
import shutil
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"
CLEAR = "\033[2J\033[H"


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _center_line(text: str, width: int) -> str:
    visible = len(_strip_ansi(text))
    pad = max((width - visible) // 2, 0)
    return (" " * pad) + text


def _render(lines: list[str], width: int) -> str:
    return "\n".join(_center_line(line, width) for line in lines)


def _frame_sniper_notepad(bullet_step: int = 0) -> list[str]:
    shot = " " * bullet_step + f"{YELLOW}*{RESET}" if bullet_step > 0 else ""
    return [
        "",
        f"{DIM}                 __{RESET}                                      {WHITE}.----------------------.{RESET}",
        f"{DIM}          _    _|==|______________________________________{WHITE}| malware.sh          |{RESET}",
        f"{DIM}      _  / )-'-|  |----.___/---<__________________________{WHITE}| curl evil | bash    |{RESET}",
        f"{DIM}     / \\/ /    |  |{RESET} {shot:<35}                     {WHITE}| nc -e /bin/sh ...   |{RESET}",
        f"{DIM}    /    /     |__|{RESET}                                 {WHITE}| LD_PRELOAD=/tmp/x.so|{RESET}",
        f"{DIM}   /_/\\_/       /_/ {RESET}                                 {WHITE}'----------------------'{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_impact() -> list[str]:
    return [
        "",
        f"{DIM}                 __{RESET}                                      {RED}{BOLD} .-BOOM----------------.{RESET}",
        f"{DIM}          _    _|==|______________________________________{RED}{BOLD}/ *  *  *  *  *  *    /{RESET}",
        f"{DIM}      _  / )-'-|  |----.___/---<__________________________{RED}{BOLD}|  ###  ##   ####     |{RESET}",
        f"{DIM}     / \\/ /    |  |{RESET} {YELLOW}>>>===>{RESET}                            {RED}{BOLD}|  ####   #####  *    |{RESET}",
        f"{DIM}    /    /     |__|{RESET}                                 {RED}{BOLD}\\ *   ####   ###   */{RESET}",
        f"{DIM}   /_/\\_/       /_/ {RESET}                                 {RED}{BOLD} '--------------------'{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_destroyed() -> list[str]:
    return [
        "",
        f"{DIM}                 __{RESET}",
        f"{DIM}          _    _|==|____________________{RED}*     *     *{RESET}",
        f"{DIM}      _  / )-'-|  |----.___/---<______{RED}***   **   **{RESET}",
        f"{DIM}     / \\/ /    |  |{RESET}               {RED}####  ####  ###{RESET}",
        f"{DIM}    /    /     |__|{RESET}              {RED}**  **  ***  **{RESET}",
        f"{DIM}   /_/\\_/       /_/ {RESET}",
        "",
        f"{CYAN}{BOLD}Tenacity in Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_tenacity_linux() -> list[str]:
    return [
        "",
        "",
        "",
        f"{CYAN}{BOLD}Tenacity in Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_transition_1() -> list[str]:
    return [
        "",
        "",
        "",
        f"{CYAN}{BOLD}Tenaci   Linux{RESET}",
        "",
        f"{DIM}Comprehensive Linux Persistence Detection{RESET}",
        "",
    ]


def _frame_transition_2() -> list[str]:
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

    frames: list[tuple[list[str], float]] = []

    # Bullet travel
    for step in (0, 8, 16, 24, 32):
        frames.append((_frame_sniper_notepad(step), 0.30))

    # Impact and reveal
    frames.extend(
        [
            (_frame_impact(), 0.45),
            (_frame_destroyed(), 0.55),
            (_frame_tenacity_linux(), 0.70),
            (_frame_transition_1(), 0.55),
            (_frame_transition_2(), 0.45),
            (_frame_tenax_big(), 1.00),
        ]
    )

    total_weight = sum(weight for _, weight in frames)
    scale = duration / total_weight if total_weight else 1.0

    try:
        for lines, weight in frames:
            sys.stdout.write(CLEAR)
            sys.stdout.write(_render(lines, width))
            sys.stdout.write("\n")
            sys.stdout.flush()
            time.sleep(weight * scale)

        sys.stdout.write(CLEAR)
        sys.stdout.flush()
    except KeyboardInterrupt:
        sys.stdout.write(RESET + "\n")
        sys.stdout.flush()