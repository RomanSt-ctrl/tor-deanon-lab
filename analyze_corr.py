#!/usr/bin/env python3
"""Аналіз кореляційної атаки (4.2).
Клієнт: мережевий спостерігач (провайдер) бачить з'єднання клієнта з його guard — вхідний трафік.
Сервер (onion-сервіс), три позиції спостерігача:
  «мережа: сумарно»        — увесь вихідний трафік сервера (провайдер хостингу, без розрізнення з'єднань);
  «мережа: TLS-з'єднання»  — окремо кожне з'єднання сервера з його guard (розрізняються за IP);
  «ланцюжок»               — окремо кожен ланцюжок (події CIRC_BW, 1 с): так бачить шкідливий guard
                             сервісу або той, хто контролює сервер; якщо circbw.jsonl немає — пропускається.
Для кожного завантаження клієнта (подія з events*.jsonl) береться вікно трафіку клієнта і шукається
найкращий збіг із рядом сервера при зсуві d ∈ LAGS (затримка Tor, відкалібрована: +0,5…0,8 с).
Оцінка: мережа — максимум кореляції Пірсона r (ряди 0,1 с, згладжені ковзним середнім 1 с);
ланцюжок — r × V, де V = менший/більший обсяг за вікно (guard бачить точний обсяг ланцюжка).
Вікна: «завантаження» [t0 − 1 с; t1 + 2 с] (межі сплеску видно на боці клієнта) і фіксовані 10/30/60 с від t0.
Подія «позитивна», якщо клієнт справді завантажував з нашого onion-сервісу. Метрики: ROC AUC,
TPR при FPR = 1 % і 5 %, ідентифікація top-1: чи має справжній клієнт найбільшу оцінку серед усіх 5.
Використання: python3 analyze_corr.py <папка з client*.pcap, server.pcap, events*.jsonl[, circbw.jsonl]> <папка результатів>"""
import csv
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

matplotlib.use("Agg")
import matplotlib.pyplot as plt

VM_IP = bytes([10, 0, 2, 15])
BIN = 0.1                                   # с, крок мережевого ряду
SMOOTH = 10                                 # ковзне середнє: 10 кроків = 1 с
LAGS_NET = range(0, 21)                     # зсув 0…2 с кроком 0,1 с
LAGS_CIRC = range(0, 4)                     # зсув 0…3 с кроком 1 с (CIRC_BW описує попередню секунду)
WINDOWS = ("завантаження", 10, 30, 60)


def packets(pcap):
    """(час, вихідний?, IP другої сторони, довжина) для кожного пакета IPv4/TCP — з'єднання Tor."""
    with open(pcap, "rb") as f:
        f.read(24)
        while hdr := f.read(16):
            sec, usec, caplen, length = struct.unpack("<IIII", hdr)
            frame = f.read(caplen)
            if struct.unpack_from("!H", frame, 12)[0] != 0x0800 or frame[23] != 6:
                continue
            out = frame[26:30] == VM_IP
            yield sec + usec / 1e6, out, frame[30:34] if out else frame[26:30], length


def flows(pcap, min_share=0.01):
    """IP вузлів (guard), з якими VM обмінювалась ≥ min_share усього трафіку."""
    vol = defaultdict(int)
    for _, _, peer, length in packets(pcap):
        vol[peer] += length
    return [p for p, v in vol.items() if v >= min_share * sum(vol.values())]


def series(pcap, t_start, n_bins, peer=None, smooth=True):
    """Байти за кожні BIN секунд окремо для вхідного і вихідного напрямку (відносно VM);
    peer — лише з'єднання з цим вузлом (спостерігач розрізняє TLS-з'єднання за адресою)."""
    inc, out = np.zeros(n_bins), np.zeros(n_bins)
    for t, is_out, p, length in packets(pcap):
        b = int((t - t_start) / BIN)
        if 0 <= b < n_bins and (peer is None or p == peer):
            (out if is_out else inc)[b] += length
    if not smooth:
        return inc, out
    kernel = np.ones(SMOOTH) / SMOOTH       # згладжування: Tor «розмазує» сплески по ланцюжку
    return np.convolve(inc, kernel, "same"), np.convolve(out, kernel, "same")


def circuits(path, t_start, n_sec):
    """Байти, записані сервером у кожен ланцюжок, за кожну секунду (з журналу CIRC_BW)."""
    c = defaultdict(lambda: np.zeros(n_sec))
    for line in open(path):
        r = json.loads(line)
        b = int(r["t"] - t_start)
        if 0 <= b < n_sec and r["written"]:
            c[r["id"]][b] += r["written"]
    return list(c.values())


def owner(c, ev, t_start):
    """Справжній власник ланцюжка (з журналу подій): клієнт, чиї own-завантаження покривають найбільше його байтів."""
    cover = defaultdict(float)
    for e in ev:
        if e["own"]:
            cover[e["vm"]] += c[int(e["t0"] - t_start):int(e["t1"] - t_start) + 4].sum()
    return max(cover, key=cover.get) if cover and max(cover.values()) > 0 else None


def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1]) if a.std() > 0 and b.std() > 0 else 0.0


def score(x, ys, i, j, lags, volume=False):
    """Найкращий збіг x[i:j] з будь-яким рядом із ys, зсунутим на d ∈ lags (сервер раніше за клієнта)."""
    a = x[i:j]
    if a.sum() == 0:
        return 0.0
    best = -1.0
    for y in ys:
        for d in lags:
            if i - d < 0 or j - d > len(y):
                continue
            b = y[i - d:j - d]
            if b.sum() == 0:
                continue
            s = pearson(a, b)
            if volume:
                s *= min(a.sum(), b.sum()) / max(a.sum(), b.sum())
            best = max(best, s)
    return best


def bounds(e, w, t_start, step):
    """Індекси вікна в ряду з кроком step."""
    if w == "завантаження":
        return int((e["t0"] - 1 - t_start) / step), int(np.ceil((e["t1"] + 2 - t_start) / step))
    i = int((e["t0"] - t_start) / step)
    return i, i + int(w / step)


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    events = [json.loads(l) for f in sorted(src.glob("events*.jsonl")) for l in open(f)]
    vms = sorted({e["vm"] for e in events})
    t_start = min(e["t0"] for e in events) - 10
    n_sec = int(max(e["t1"] for e in events) + 80 - t_start)
    n_bins = n_sec * round(1 / BIN)

    srv_in, srv_out = series(src / "server.pcap", t_start, n_bins)
    srv_flows = [series(src / "server.pcap", t_start, n_bins, p)[1] for p in flows(src / "server.pcap")]
    cli = {vm: series(src / f"client{vm}.pcap", t_start, n_bins)[0] for vm in vms}
    observers = {"мережа: сумарно": ([srv_out], cli, LAGS_NET, BIN, False),
                 "мережа: TLS-з'єднання": (srv_flows, cli, LAGS_NET, BIN, False)}
    circ = []
    if (src / "circbw.jsonl").exists():
        circ = circuits(src / "circbw.jsonl", t_start, n_sec)
        cli_1s = {vm: series(src / f"client{vm}.pcap", t_start, n_bins, smooth=False)[0]
                  .reshape(-1, round(1 / BIN)).sum(1) for vm in vms}
        observers["ланцюжок (CIRC_BW)"] = (circ, cli_1s, LAGS_CIRC, 1.0, True)

    ev = [e for e in events if not e["own"] or e["code"] == "200"]
    owners = [owner(c, ev, t_start) for c in circ]
    print(f"подій: {len(events)}, у аналізі: {len(ev)} (own {sum(e['own'] for e in ev)}, "
          f"decoy {sum(not e['own'] for e in ev)}), відкинуто own з помилкою: {len(events) - len(ev)}")
    print(f"трафік сервера: вхідний {srv_in.sum() / 1e6:.0f} МБ, вихідний {srv_out.sum() / 1e6:.0f} МБ; "
          f"з'єднань з guard: {len(srv_flows)} ({', '.join(f'{x.sum() / srv_out.sum():.0%}' for x in srv_flows)}); "
          f"ланцюжків з даними (CIRC_BW): {len(circ)}")

    rows = []
    fig, axes = plt.subplots(1, len(observers), figsize=(5 * len(observers), 4.6), squeeze=False)
    for ax, (obs, (ys, xs, lags, step, volume)) in zip(axes[0], observers.items()):
        for w in WINDOWS:
            y_true, y_score, ident = [], [], []
            for e in ev:
                i, j = bounds(e, w, t_start, step)
                s = {vm: score(xs[vm], ys, i, j, lags, volume) for vm in vms}
                y_true.append(e["own"])
                y_score.append(s[e["vm"]])
                if e["own"] and not volume:
                    ident.append(max(s, key=s.get) == e["vm"])
                elif e["own"]:
                    # ланцюжок: беремо ланцюжок цього завантаження (власник за журналом, найбільший обсяг у вікні)
                    # і питаємо, чий клієнтський потік з ним збігається найкраще
                    mine = [c for c, o in zip(circ, owners) if o == e["vm"]]
                    if mine:
                        c_star = max(mine, key=lambda c: c[max(i, 0):j].sum())
                        s2 = {vm: score(xs[vm], [c_star], i, j, lags, volume) for vm in vms}
                        ident.append(max(s2, key=s2.get) == e["vm"])
            y_true, y_score = np.array(y_true), np.array(y_score)
            auc = roc_auc_score(y_true, y_score)
            fpr, tpr, _ = roc_curve(y_true, y_score)
            rows.append({"observer": obs, "window": w, "events": len(ev), "auc": round(auc, 3),
                         "tpr_at_fpr1": round(float(np.interp(0.01, fpr, tpr)), 3),
                         "tpr_at_fpr5": round(float(np.interp(0.05, fpr, tpr)), 3),
                         "identification_top1": round(float(np.mean(ident)), 3),
                         "median_score_own": round(float(np.median(y_score[y_true])), 3),
                         "median_score_decoy": round(float(np.median(y_score[~y_true])), 3)})
            print(rows[-1])
            ax.plot(fpr, tpr, label=f"{w if isinstance(w, str) else f'{w} с'} (AUC = {auc:.2f})")
        ax.plot([0, 1], [0, 1], "k:", lw=0.8)
        ax.set_xlabel("частка хибних спрацювань (FPR)")
        ax.set_ylabel("частка виявлених (TPR)")
        ax.set_title(f"Сервер: {obs}", fontsize=10)
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8, title="вікно", title_fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "corr_roc.png", dpi=150)
    with open(out / "corr_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    # ілюстрація: own-подія середнього розміру (> 1 МБ) — клієнт, сумарний трафік сервера, найактивніший ланцюжок
    own = sorted((e for e in ev if e["own"] and e["bytes"] > 1e6), key=lambda e: e["bytes"])
    e = own[len(own) // 2]
    to_s = round(1 / BIN)
    i = int(e["t0"] - 3 - t_start)
    t = np.arange(30) - 3
    per_s = lambda x: x[i * to_s:(i + 30) * to_s].reshape(-1, to_s).sum(1) / 1e3
    fig, ax = plt.subplots(figsize=(8, 3.5))
    ax.step(t, per_s(series(src / f"client{e['vm']}.pcap", t_start, n_bins, smooth=False)[0]), where="post",
            label=f"клієнт lab-{e['vm']}: вхідний")
    ax.step(t, per_s(series(src / "server.pcap", t_start, n_bins, smooth=False)[1]), where="post", alpha=0.7,
            label="сервер: сумарно")
    if circ:
        best = max(circ, key=lambda c: c[i:i + 30].sum())
        ax.step(t, best[i:i + 30] / 1e3, where="post", alpha=0.8, label="сервер: ланцюжок (CIRC_BW)")
    ax.set_xlabel("с від початку завантаження")
    ax.set_ylabel("КБ/с")
    ax.set_title(f"{e['url'].rsplit('/', 1)[-1]} ({e['bytes'] / 1e6:.1f} МБ)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / "corr_example.png", dpi=150)


if __name__ == "__main__":
    main()
