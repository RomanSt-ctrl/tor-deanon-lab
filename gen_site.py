#!/usr/bin/env python3
"""Генерує вміст власного onion-сервісу: 20 сторінок різної структури (для website fingerprinting, 4.3)
і файли різного розміру (для кореляційної атаки, 4.2). Використання: python3 gen_site.py <папка>"""
import random
import struct
import sys
import zlib
from pathlib import Path

rng = random.Random(2026)
WORDS = ("мережа вузол трафік ланцюжок шифрування маршрут сервер клієнт пакет протокол "
         "анонімність спостерігач кореляція затримка пропускна здатність консенсус директорія").split()


def png(width, height):
    """Валідний PNG із випадковим шумом — майже не стискається, тож розмір ≈ width·height·3."""
    raw = b"".join(b"\x00" + rng.randbytes(width * 3) for _ in range(height))
    chunk = lambda t, d: struct.pack("!I", len(d)) + t + d + struct.pack("!I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 1)) + chunk(b"IEND", b""))


def text(n_words):
    return " ".join(rng.choice(WORDS) for _ in range(n_words))


def main():
    root = Path(sys.argv[1])
    (root / "img").mkdir(parents=True, exist_ok=True)
    (root / "files").mkdir(exist_ok=True)
    links = []
    for p in range(1, 21):
        n_img = rng.choice([0, 1, 2, 4, 8, 12])
        side = rng.choice([64, 128, 256, 400])
        n_words = rng.choice([200, 1000, 4000, 12000])
        js_kb = rng.choice([0, 20, 150])
        imgs = []
        for i in range(n_img):
            name = f"p{p:02d}_{i}.png"
            (root / "img" / name).write_bytes(png(side, side))
            imgs.append(f'<img src="/img/{name}" width="{side}" height="{side}">')
        script = ""
        if js_kb:
            (root / f"p{p:02d}.js").write_text("var d=" + repr(rng.randbytes(js_kb * 512).hex()) + ";")
            script = f'<script src="/p{p:02d}.js"></script>'
        html = (f"<!doctype html><html><head><meta charset='utf-8'><title>Сторінка {p}</title>{script}</head>"
                f"<body><h1>Сторінка {p}</h1><p>{text(n_words)}</p>{''.join(imgs)}"
                f"<p><a href='/'>На головну</a></p></body></html>")
        (root / f"p{p:02d}.html").write_text(html)
        links.append(f'<li><a href="/p{p:02d}.html">Сторінка {p}</a> — {n_img} зобр. {side}px, '
                     f'{n_words} слів, JS {js_kb} КБ</li>')
    (root / "index.html").write_text("<!doctype html><html><head><meta charset='utf-8'><title>Lab onion</title>"
                                     f"</head><body><h1>Лабораторний onion-сервіс</h1><ul>{''.join(links)}</ul>"
                                     "</body></html>")
    for kb in (100, 300, 1000, 3000):            # файли для 4.2: різна тривалість передачі
        (root / "files" / f"f{kb}k.bin").write_bytes(rng.randbytes(kb * 1024))
    print("\n".join(links))


if __name__ == "__main__":
    main()
