
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

ANSI_RESET = "\033[0m"
ANSI_HIDE_CURSOR = "\033[?25l"
ANSI_SHOW_CURSOR = "\033[?25h"
ANSI_CLEAR = "\033[2J\033[H"

COLOR_LOGO = "\033[38;5;196m"
COLOR_LOGO_DIM = "\033[38;5;160m"
COLOR_DEBRIS_1 = "\033[38;5;208m"
COLOR_DEBRIS_2 = "\033[38;5;214m"
COLOR_DEBRIS_3 = "\033[38;5;250m"
COLOR_DUST = "\033[38;5;240m"


def _clear_screen() -> None:
    sys.stdout.write(ANSI_CLEAR)
    sys.stdout.flush()


def _hide_cursor() -> None:
    sys.stdout.write(ANSI_HIDE_CURSOR)
    sys.stdout.flush()


def _show_cursor() -> None:
    sys.stdout.write(ANSI_SHOW_CURSOR)
    sys.stdout.flush()


def _terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size((140, 40))
    return size.columns, size.lines


def _center_lines(lines: list[str], width: int, height: int) -> tuple[list[str], int, int]:
    logo_height = len(lines)
    logo_width = max((len(line) for line in lines), default=0)

    top_pad = max(0, (height - logo_height) // 2)
    left_pad = max(0, (width - logo_width) // 2)

    centered: list[str] = []
    centered.extend([""] * top_pad)
    for line in lines:
        centered.append((" " * left_pad) + line)

    return centered, left_pad, top_pad


def _render_frame(lines: list[str], color: str = COLOR_LOGO) -> None:
    width, height = _terminal_size()
    centered, _, _ = _center_lines(lines, width, height)
    _clear_screen()
    rendered: list[str] = []
    for line in centered:
        if line.strip():
            rendered.append(f"{color}{line}{ANSI_RESET}")
        else:
            rendered.append(line)
    sys.stdout.write("\n".join(rendered))
    sys.stdout.flush()


def _render_canvas(canvas: list[list[str]], color_map: dict[tuple[int, int], str] | None = None) -> None:
    _clear_screen()
    out_lines: list[str] = []

    for y, row in enumerate(canvas):
        current_color = None
        line_parts: list[str] = []
        for x, ch in enumerate(row):
            color = color_map.get((x, y)) if color_map else None
            if color != current_color:
                if current_color is not None:
                    line_parts.append(ANSI_RESET)
                if color is not None:
                    line_parts.append(color)
                current_color = color
            line_parts.append(ch)
        if current_color is not None:
            line_parts.append(ANSI_RESET)
        out_lines.append("".join(line_parts).rstrip())

    sys.stdout.write("\n".join(out_lines))
    sys.stdout.flush()


def _make_canvas(lines: list[str], pad_x: int = 8, pad_y: int = 4) -> tuple[list[list[str]], int, int]:
    height = len(lines) + (pad_y * 2)
    width = max((len(line) for line in lines), default=0) + (pad_x * 2)

    canvas = [[" " for _ in range(width)] for _ in range(height)]

    for y, line in enumerate(lines, start=pad_y):
        for x, ch in enumerate(line, start=pad_x):
            canvas[y][x] = ch

    return canvas, width, height


def _expand_to_terminal(lines: list[str]) -> tuple[list[list[str]], int, int, int, int]:
    term_w, term_h = _terminal_size()
    centered, left_pad, top_pad = _center_lines(lines, term_w, term_h)

    canvas = [[" " for _ in range(term_w)] for _ in range(term_h)]

    for y, line in enumerate(centered):
        if y >= term_h:
            break
        for x, ch in enumerate(line[:term_w]):
            canvas[y][x] = ch

    return canvas, term_w, term_h, left_pad, top_pad


def _glow_color(frame_index: int, total_frames: int) -> str:
    pulse = frame_index % 4
    if pulse in (0, 2):
        return COLOR_LOGO
    return COLOR_LOGO_DIM


def _grow_logo(total_duration: float = 2.5) -> None:
    frame_count = len(LOGO_STAGES)
    if frame_count == 0:
        return

    delays = [total_duration / frame_count] * frame_count

    for idx, (lines, delay) in enumerate(zip(LOGO_STAGES, delays), start=1):
        subframes = 4 if idx == frame_count else 3
        per_subframe = delay / subframes
        for sub in range(subframes):
            _render_frame(lines, color=_glow_color(sub, subframes))
            time.sleep(per_subframe)


def _particle_char() -> str:
    return random.choice([".", ",", "`", "'", "*", ":", ";"])


def _particle_color() -> str:
    return random.choice([COLOR_DEBRIS_1, COLOR_DEBRIS_2, COLOR_DEBRIS_3])


def _impact_dust(canvas: list[list[str]], particles: list[dict[str, float | str]], floor_y: int, width: int) -> list[dict[str, float | str]]:
    for particle in particles:
        py = int(particle["y"])
        if py >= floor_y - 1:
            center_x = int(particle["x"])
            for dx in (-2, -1, 0, 1, 2):
                x = center_x + dx
                if 0 <= x < width and 0 <= floor_y < len(canvas):
                    if canvas[floor_y][x] == " ":
                        canvas[floor_y][x] = random.choice([".", "·"])
    return particles


def _crumble_logo(lines: list[str], frame_delay: float = 0.05) -> None:
    canvas, width, height, _, _ = _expand_to_terminal(lines)

    particles: list[dict[str, float | str]] = []
    occupied_positions: list[tuple[int, int]] = []

    for y in range(height):
        for x in range(width):
            if canvas[y][x] != " ":
                occupied_positions.append((x, y))

    random.shuffle(occupied_positions)

    floor_y = height - 2
    crumble_batches = max(24, len(occupied_positions) // 20)
    batch_size = max(1, len(occupied_positions) // crumble_batches)

    for i in range(0, len(occupied_positions), batch_size):
        batch = occupied_positions[i:i + batch_size]

        for x, y in batch:
            if canvas[y][x] != " ":
                particles.append(
                    {
                        "x": float(x),
                        "y": float(y),
                        "vx": float(random.choice([-0.8, -0.4, 0.0, 0.4, 0.8])),
                        "vy": float(random.uniform(0.2, 0.6)),
                        "char": _particle_char(),
                        "color": _particle_color(),
                    }
                )
                canvas[y][x] = " "

        for _ in range(2):
            next_canvas = [row[:] for row in canvas]
            color_map: dict[tuple[int, int], str] = {}
            next_particles: list[dict[str, float | str]] = []

            for particle in particles:
                px = float(particle["x"])
                py = float(particle["y"])
                vx = float(particle["vx"])
                vy = float(particle["vy"])

                draw_x = int(round(px))
                draw_y = int(round(py))

                if 0 <= draw_x < width and 0 <= draw_y < height:
                    next_canvas[draw_y][draw_x] = str(particle["char"])
                    color_map[(draw_x, draw_y)] = str(particle["color"])

                    trail_y = draw_y - 1
                    if 0 <= trail_y < height and next_canvas[trail_y][draw_x] == " ":
                        next_canvas[trail_y][draw_x] = "·"
                        color_map[(draw_x, trail_y)] = COLOR_DUST

                vx *= 0.99
                vy += 0.14

                nx = px + vx
                ny = py + vy

                if ny >= floor_y:
                    ny = float(floor_y)
                    vx *= 0.35
                    vy *= -0.15
                    if abs(vx) < 0.05 and abs(vy) < 0.05:
                        continue

                if 0 <= nx < width and ny < height:
                    particle["x"] = max(0.0, min(float(width - 1), nx))
                    particle["y"] = ny
                    particle["vx"] = vx
                    particle["vy"] = vy
                    next_particles.append(particle)

            _impact_dust(next_canvas, particles, floor_y, width)
            _render_canvas(next_canvas, color_map)
            particles = next_particles
            time.sleep(frame_delay)

    settling_frames = 18
    for _ in range(settling_frames):
        next_canvas = [[" " for _ in range(width)] for _ in range(height)]
        color_map: dict[tuple[int, int], str] = {}
        next_particles: list[dict[str, float | str]] = []

        for particle in particles:
            px = float(particle["x"])
            py = float(particle["y"])
            vx = float(particle["vx"])
            vy = float(particle["vy"])

            draw_x = int(round(px))
            draw_y = int(round(py))

            if 0 <= draw_x < width and 0 <= draw_y < height:
                next_canvas[draw_y][draw_x] = str(particle["char"])
                color_map[(draw_x, draw_y)] = str(particle["color"])

                trail_y = draw_y - 1
                if 0 <= trail_y < height and next_canvas[trail_y][draw_x] == " ":
                    next_canvas[trail_y][draw_x] = "·"
                    color_map[(draw_x, trail_y)] = COLOR_DUST

            vx *= 0.97
            vy += 0.18

            nx = px + vx
            ny = py + vy

            if ny >= floor_y:
                ny = float(floor_y)
                vx *= 0.25
                vy *= -0.08
                if abs(vx) < 0.03 and abs(vy) < 0.03:
                    continue

            if 0 <= nx < width and ny < height:
                particle["x"] = max(0.0, min(float(width - 1), nx))
                particle["y"] = ny
                particle["vx"] = vx
                particle["vy"] = vy
                next_particles.append(particle)

        _impact_dust(next_canvas, particles, floor_y, width)

        for x in range(width):
            if next_canvas[floor_y][x] == " " and random.random() < 0.05:
                next_canvas[floor_y][x] = "·"
                color_map[(x, floor_y)] = COLOR_DUST

        _render_canvas(next_canvas, color_map)
        particles = next_particles
        time.sleep(frame_delay)

    fade_frames = 8
    for i in range(fade_frames):
        fade_canvas = [[" " for _ in range(width)] for _ in range(height)]
        color_map: dict[tuple[int, int], str] = {}
        dust_probability = max(0.0, 0.45 - (i * 0.05))

        for x in range(width):
            if random.random() < dust_probability:
                fade_canvas[floor_y][x] = "·"
                color_map[(x, floor_y)] = COLOR_DUST

        _render_canvas(fade_canvas, color_map)
        time.sleep(0.04)

    _clear_screen()


def show_startup_banner(duration: float = 5.0) -> None:
    try:
        _hide_cursor()
        _grow_logo(total_duration=2.5)
        time.sleep(2.0)
        _crumble_logo(LOGO_STAGES[-1], frame_delay=0.05)
        _clear_screen()
        sys.stdout.write("\033[H")
        sys.stdout.flush()
    finally:
        _show_cursor()