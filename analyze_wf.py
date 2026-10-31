#!/usr/bin/env python3
"""Аналіз website fingerprinting (4.3).
Траса = послідовність пакетів (час, напрям) між клієнтом і guard; чисті ACK без даних відкидаються.
Ознаки: (1) k-FP-подібні (Hayes, Danezis, 2016) — кількості, сплески, інтервали, «концентрація»
пакетів, швидкість; (2) CUMUL (Panchenko et al., 2016) — кумулятивна сума розмірів у 100 точках.
Оцінка: закритий світ (лише 26 відстежуваних класів) — 5-кратна стратифікована перехресна перевірка
і перенос «навчання на 4 VM → перевірка на 5-й»; відкритий світ — невідстежувані сайти в тесті
не трапляються в навчанні (групи за доменом).
Використання: python3 analyze_wf.py <папка з vm*/…pcap і visits*.jsonl> <папка результатів>"""
import csv
import json
import struct
import sys
from collections import defaultdict
from multiprocessing import Pool
from pathlib import Path

import matplotlib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

matplotlib.use("Agg")
import matplotlib.pyplot as plt

VM_IP = bytes([10, 0, 2, 15])
SEED = 2026


def trace(path):
    """[(час від початку, ±розмір)]: + вихідний (клієнт → guard), − вхідний."""
    pk = []
    with open(path, "rb") as f:
        f.read(24)
        while hdr := f.read(16):
            sec, usec, caplen, length = struct.unpack("<IIII", hdr)
            fr = f.read(caplen)
            if struct.unpack_from("!H", fr, 12)[0] != 0x0800 or fr[23] != 6:
                continue
            ihl = (fr[14] & 15) * 4
            tot = struct.unpack_from("!H", fr, 16)[0]
            payload = tot - ihl - (fr[14 + ihl + 12] >> 4) * 4
            if payload <= 0:
                continue                                   # чистий ACK
            pk.append((sec + usec / 1e6, payload if fr[26:30] == VM_IP else -payload))
    if not pk:
        return np.zeros((0, 2))
    a = np.array(pk)
    a[:, 0] -= a[0, 0]
    return a


def stats(x):
    x = np.asarray(x, float)
    if len(x) == 0:
        return [0] * 6
    return [x.mean(), x.std(), x.min(), x.max(), np.percentile(x, 25), np.percentile(x, 75)]


def kfp(a):
    t, s = a[:, 0], a[:, 1]
    out, inc = s > 0, s < 0
    n = len(s) or 1
    f = [len(s), out.sum(), inc.sum(), out.sum() / n, inc.sum() / n,
         s[out].sum(), -s[inc].sum(), t[-1] if len(t) else 0]
    f += stats(np.diff(t)) + stats(np.diff(t[out])) + stats(np.diff(t[inc]))
    f += [out[:30].sum(), inc[:30].sum(), out[-30:].sum(), inc[-30:].sum()]
    conc = [out[i:i + 20].sum() for i in range(0, len(s), 20)]           # вихідних у кожних 20 пакетах
    f += stats(conc) + (conc + [0] * 30)[:30]
    sec = np.bincount(t.astype(int)) if len(t) else np.zeros(1)            # пакетів за секунду
    f += stats(sec) + list(np.pad(sec, (0, 20))[:20])
    bursts, cur = [], 0                                                    # сплески вхідних пакетів
    for v in s:
        if v < 0:
            cur += 1
        elif cur:
            bursts.append(cur)
            cur = 0
    bursts += [cur] if cur else []
    f += [len(bursts)] + stats(bursts) + (bursts + [0] * 20)[:20]
    for q in (0.25, 0.5, 0.75, 1.0):                                       # коли передано q обсягу
        c = np.cumsum(np.abs(s))
        f.append(t[np.searchsorted(c, q * c[-1])] if len(c) else 0)
    return f


def cumul(a, n=100):
    c = np.cumsum(a[:, 1]) if len(a) else np.zeros(1)
    ca = np.cumsum(np.abs(a[:, 1])) if len(a) else np.zeros(1)
    grid = np.linspace(0, ca[-1], n)
    n_out = int((a[:, 1] > 0).sum()) if len(a) else 0
    return [len(a), n_out, len(a) - n_out, ca[-1]] + list(np.interp(grid, ca, c))


def features(path):
    a = trace(path)
    return kfp(a), cumul(a), len(a)


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    recs = [json.loads(l) for f in sorted(src.glob("vm*/visits*.jsonl")) for l in open(f)]
    recs = [r for r in recs if r["status"] == "ok"]
    paths = [src / f"vm{r['vm']}" / f"{r['label']}__vm{r['vm']}_i{r['i']:04d}.pcap" for r in recs]
    with Pool() as pool:
        feats = pool.map(features, paths, chunksize=8)
    keep = [i for i, f in enumerate(feats) if f[2] >= 20]                  # порожні/обірвані траси
    recs = [recs[i] for i in keep]
    Xk = np.nan_to_num(np.array([feats[i][0] for i in keep], float))
    Xc = np.nan_to_num(np.array([feats[i][1] for i in keep], float))
    y = np.array([r["label"] for r in recs])
    vm = np.array([r["vm"] for r in recs])
    mon = np.array([not l.startswith("unmon_") for l in y])
    print(f"трас ok: {len(paths)}, після відсіву (< 20 пакетів з даними): {len(recs)}; "
          f"відстежуваних {mon.sum()} ({len(set(y[mon]))} класів), невідстежуваних {(~mon).sum()} "
          f"({len(set(y[~mon]))} сайтів); ознак k-FP {Xk.shape[1]}, CUMUL {Xc.shape[1]}")

    models = {"k-FP + Random Forest": (Xk, lambda: RandomForestClassifier(500, n_jobs=-1, random_state=SEED)),
              "CUMUL + SVM (RBF)": (Xc, lambda: make_pipeline(StandardScaler(), SVC(C=2048, gamma="scale")))}
    rows = []
    # --- закритий світ: 5-кратна перехресна перевірка
    ym = y[mon]
    for name, (X, mk) in models.items():
        acc, pred_all = [], np.empty(len(ym), object)
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=SEED).split(X[mon], ym):
            m = mk().fit(X[mon][tr], ym[tr])
            p = m.predict(X[mon][te])
            pred_all[te] = p
            acc.append(accuracy_score(ym[te], p))
        rows.append({"experiment": "closed-world 5-fold", "model": name,
                     "accuracy": round(np.mean(acc), 4), "std": round(np.std(acc), 4)})
        print(rows[-1])
        if name.startswith("k-FP"):
            labels = sorted(set(ym))
            cm = confusion_matrix(ym, pred_all, labels=labels, normalize="true")
            fig, ax = plt.subplots(figsize=(9, 8))
            ax.imshow(cm, cmap="Blues", vmin=0, vmax=1)
            ax.set_xticks(range(len(labels)), labels, rotation=90, fontsize=7)
            ax.set_yticks(range(len(labels)), labels, fontsize=7)
            ax.set_xlabel("передбачений клас")
            ax.set_ylabel("справжній клас")
            ax.set_title("WF, закритий світ: k-FP + Random Forest (нормовано за рядками)")
            fig.tight_layout()
            fig.savefig(out / "wf_confusion.png", dpi=150)
            per_class = {l: cm[i, i] for i, l in enumerate(labels)}
            worst = sorted(per_class.items(), key=lambda kv: kv[1])[:5]
            print("  найгірші класи:", ", ".join(f"{k} {v:.2f}" for k, v in worst))

    # --- перенос між машинами: навчання на 4 VM, перевірка на 5-й
    for name, (X, mk) in models.items():
        accs = []
        for v in sorted(set(vm)):
            tr, te = mon & (vm != v), mon & (vm == v)
            accs.append(accuracy_score(y[te], mk().fit(X[tr], y[tr]).predict(X[te])))
        rows.append({"experiment": "closed-world leave-one-VM-out", "model": name,
                     "accuracy": round(np.mean(accs), 4), "std": round(np.std(accs), 4)})
        print(rows[-1])

    # --- крива навчання: точність від кількості відвідувань на клас (k-FP + RF)
    rng = np.random.default_rng(SEED)
    idx_by = defaultdict(list)
    for i in np.flatnonzero(mon):
        idx_by[y[i]].append(i)
    curve = []
    for n_train in (5, 10, 20, 40, 60):
        accs = []
        for rep in range(3):
            tr, te = [], []
            for l, idx in idx_by.items():
                idx = rng.permutation(idx)
                tr += list(idx[:n_train])
                te += list(idx[n_train:n_train + 15])
            m = models["k-FP + Random Forest"][1]().fit(Xk[tr], y[tr])
            accs.append(accuracy_score(y[te], m.predict(Xk[te])))
        curve.append((n_train, np.mean(accs), np.std(accs)))
        rows.append({"experiment": f"learning curve n_train={n_train}", "model": "k-FP + Random Forest",
                     "accuracy": round(np.mean(accs), 4), "std": round(np.std(accs), 4)})
    print("крива навчання:", [(n, round(a, 3)) for n, a, _ in curve])

    # --- відкритий світ: невідстежувані сайти тесту не трапляються в навчанні
    groups = np.array([l if l.startswith("unmon_") else "" for l in y])
    unmon_sites = sorted(set(groups[~mon]))
    fold_of_site = {s: k % 5 for k, s in enumerate(rng.permutation(unmon_sites))}
    fold = np.where(mon, rng.integers(0, 5, len(y)), [fold_of_site.get(g, 0) for g in groups])
    y_open = np.where(mon, y, "unmon")
    pred = np.empty(len(y), object)
    conf = np.zeros(len(y))
    for k in range(5):
        tr, te = fold != k, fold == k
        m = models["k-FP + Random Forest"][1]().fit(Xk[tr], y_open[tr])
        pr = m.predict_proba(Xk[te])
        pred[te] = m.classes_[pr.argmax(1)]
        conf[te] = pr.max(1)
    ow = []
    for thr in np.linspace(0, 0.95, 20):
        p = np.where((pred != "unmon") & (conf >= thr), pred, "unmon")
        tp = ((p == y_open) & mon).sum()
        wp = ((p != y_open) & mon & (p != "unmon")).sum()
        fp = ((p != "unmon") & ~mon).sum()
        precision = tp / max(tp + wp + fp, 1)
        recall = tp / mon.sum()
        ow.append((thr, precision, recall, fp / max((~mon).sum(), 1)))
    best = max(ow, key=lambda r: 2 * r[1] * r[2] / max(r[1] + r[2], 1e-9))
    rows.append({"experiment": f"open-world (best F1, threshold {best[0]:.2f})", "model": "k-FP + Random Forest",
                 "accuracy": f"precision {best[1]:.3f}, recall {best[2]:.3f}, FPR {best[3]:.3f}", "std": ""})
    print(rows[-1])

    with open(out / "wf_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    n, a, e = zip(*curve)
    axes[0].errorbar(n, a, yerr=e, marker="o")
    axes[0].set_xlabel("відвідувань на клас у навчанні")
    axes[0].set_ylabel("точність (закритий світ)")
    axes[0].set_title("Крива навчання, k-FP + RF")
    axes[0].grid(alpha=0.3)
    _, P, R, F = zip(*ow)
    axes[1].plot(R, P, marker=".")
    axes[1].set_xlabel("повнота (recall)")
    axes[1].set_ylabel("точність (precision)")
    axes[1].set_title("Відкритий світ: зміна порогу впевненості")
    axes[1].grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / "wf_curves.png", dpi=150)


if __name__ == "__main__":
    main()
