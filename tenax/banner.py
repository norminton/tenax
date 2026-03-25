from __future__ import annotations

import random
import shutil
import sys
import time


BASE_LOGO = [
    "TTTTTTTT EEEEEEEE NNN   NN   AAAAA   XX    XX",
    "   TT    EE       NNNN  NN  AA   AA   XX  XX ",
    "   TT    EEEEE    NN NN NN  AAAAAAA    XXXX  ",
    "   TT    EE       NN  NNNN  AA   AA   XX  XX ",
    "   TT    EEEEEEEE NN   NNN  AA   AA  XX    XX",
]


def _rotate_clockwise(lines: list[str]) -> list[str]:
    width = max(len(line) for line in lines)
    padded = [line.ljust(width) for line in lines]
    return [
        "".join(padded[row][col] for row in range(len(padded) - 1, -1, -1)).rstrip()
        for col in range(width)
    ]


def _build_rotation_frames(base_lines: list[str]) -> list[list[str]]:
    frame_0 = base_lines
    frame_90 = _rotate_clockwise(frame_0)
    frame_180 = _rotate_clockwise(frame_90)
    frame_270 = _rotate_clockwise(frame_180)
    return [frame_0, frame_90, frame_180, frame_270]


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
    term_size = shutil.get_terminal_size((120, 40))
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


def _spin_logo(rotations: int = 3, frame_delay: float = 0.10) -> None:
    frames = _build_rotation_frames(BASE_LOGO)
    for _ in range(rotations):
        for frame in frames:
            _render_frame(frame)
            time.sleep(frame_delay)


def _pause(seconds: float = 2.0) -> None:
    time.sleep(seconds)


def _crumble_logo(frame_delay: float = 0.06) -> None:
    canvas, width, height = _make_canvas(BASE_LOGO, pad_x=10, pad_y=6)

    particles: list[dict[str, int | str]] = []

    occupied_positions: list[tuple[int, int]] = []
    for y in range(height):
        for x in range(width):
            if canvas[y][x] != " ":
                occupied_positions.append((x, y))

    random.shuffle(occupied_positions)

    crumble_batches = max(18, len(occupied_positions) // 18)
    batch_size = max(1, len(occupied_positions) // crumble_batches)

    for i in range(0, len(occupied_positions), batch_size):
        batch = occupied_positions[i:i + batch_size]

        for x, y in batch:
            if canvas[y][x] != " ":
                particles.append(
                    {
                        "x": x,
                        "y": y,
                        "vx": random.choice([-1, 0, 0, 1]),
                        "vy": 1,
                        "char": random.choice([".", ",", "`", "'", "*"]),
                    }
                )
                canvas[y][x] = " "

        for _ in range(2):
            next_canvas = [[" " for _ in range(width)] for _ in range(height)]
            next_particles: list[dict[str, int | str]] = []

            for particle in particles:
                px = int(particle["x"])
                py = int(particle["y"])

                if 0 <= px < width and 0 <= py < height:
                    next_canvas[py][px] = str(particle["char"])

                nx = px + int(particle["vx"])
                ny = py + int(particle["vy"])

                if ny < height:
                    particle["x"] = max(0, min(width - 1, nx))
                    particle["y"] = ny
                    next_particles.append(particle)

            for y in range(height):
                for x in range(width):
                    if canvas[y][x] != " ":
                        next_canvas[y][x] = canvas[y][x]

            particles = next_particles
            _render_canvas(next_canvas)
            time.sleep(frame_delay)

    while particles:
        next_canvas = [[" " for _ in range(width)] for _ in range(height)]
        next_particles: list[dict[str, int | str]] = []

        for particle in particles:
            px = int(particle["x"])
            py = int(particle["y"])

            if 0 <= px < width and 0 <= py < height:
                next_canvas[py][px] = str(particle["char"])

            nx = px + int(particle["vx"])
            ny = py + int(particle["vy"])

            if ny < height:
                particle["x"] = max(0, min(width - 1, nx))
                particle["y"] = ny
                next_particles.append(particle)

        particles = next_particles
        _render_canvas(next_canvas)
        time.sleep(frame_delay)

    _clear_screen()


def show_startup_banner(duration: float = 5.0) -> None:
    try:
        _hide_cursor()
        _spin_logo(rotations=3, frame_delay=0.10)
        _pause(2.0)
        _crumble_logo(frame_delay=0.06)
    finally:
        _show_cursor()