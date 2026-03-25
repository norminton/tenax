from __future__ import annotations

import random
import shutil
import sys
import time


LOGO_STAGES = [
    [
        "TENAX",
    ],
    [
        "TTTT EEEE NN  N   AA   XX  XX",
        " TT  EE   NNN N  A  A   XXXX ",
        " TT  EEE  NN NN  AAAA    XX  ",
        " TT  EE   NN  N  A  A   XXXX ",
        " TT  EEEE NN  N  A  A  XX  XX",
    ],
    [
        "TTTTTTTT EEEEEEEE NNN   NN   AAAAA   XX    XX",
        "   TT    EE       NNNN  NN  AA   AA   XX  XX ",
        "   TT    EEEEE    NN NN NN  AAAAAAA    XXXX  ",
        "   TT    EE       NN  NNNN  AA   AA   XX  XX ",
        "   TT    EEEEEEEE NN   NNN  AA   AA  XX    XX",
    ],
    [
        "TTTTTTTTTTTT  EEEEEEEEEEEE  NNNN     NNNN     AAAAAAAA      XX        XX",
        "    TTTT      EEEE          NNNNN    NNNN    AAAA  AAAA      XX      XX ",
        "    TTTT      EEEEEEEE      NNN NN   NNNN   AAAA    AAAA      XX    XX  ",
        "    TTTT      EEEE          NNN  NN  NNNN   AAAAAAAAAAAA       XXXXXX   ",
        "    TTTT      EEEEEEEEEEEE  NNN   NNNNNNN   AAAA    AAAA      XX    XX  ",
        "    TTTT      EEEEEEEEEEEE  NNN    NNNNNN   AAAA    AAAA     XX      XX ",
    ],
]


def _clear_screen() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _hide_cursor() -> None:
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def _show_cursor() -> None:
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def _center_lines(lines: list[str], width: int, height: int) -> str:
    logo_height = len(lines)
    logo_width = max((len(line) for line in lines), default=0)

    top_pad = max(0, (height - logo_height) // 2)
    left_pad = max(0, (width - logo_width) // 2)

    output: list[str] = []
    output.extend([""] * top_pad)

    for line in lines:
        output.append((" " * left_pad) + line)

    return "\n".join(output)


def _render_frame(lines: list[str]) -> None:
    term_size = shutil.get_terminal_size((140, 40))
    _clear_screen()
    sys.stdout.write(_center_lines(lines, term_size.columns, term_size.lines))
    sys.stdout.flush()


def _render_canvas(canvas: list[list[str]]) -> None:
    lines = ["".join(row).rstrip() for row in canvas]
    _render_frame(lines)


def _make_canvas(lines: list[str], pad_x: int = 8, pad_y: int = 4) -> tuple[list[list[str]], int, int]:
    height = len(lines) + (pad_y * 2)
    width = max((len(line) for line in lines), default=0) + (pad_x * 2)

    canvas = [[" " for _ in range(width)] for _ in range(height)]

    for y, line in enumerate(lines, start=pad_y):
        for x, ch in enumerate(line, start=pad_x):
            canvas[y][x] = ch

    return canvas, width, height


def _grow_logo(total_duration: float = 4.0) -> None:
    frame_count = len(LOGO_STAGES)
    if frame_count == 0:
        return

    delays = [total_duration / frame_count] * frame_count

    for lines, delay in zip(LOGO_STAGES, delays):
        _render_frame(lines)
        time.sleep(delay)


def _crumble_logo(lines: list[str], frame_delay: float = 0.06) -> None:
    canvas, width, height = _make_canvas(lines, pad_x=10, pad_y=6)

    particles: list[dict[str, int |