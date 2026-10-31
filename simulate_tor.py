#!/usr/bin/env python3
"""Імітаційна модель (Монте-Карло) вибору вузлів Tor для підрозділу 4.1.

Порушник додає в мережу власні guard- і exit-вузли з частками ваги f_g і f_e (частка ймовірності
бути обраним на позицію guard / exit). Ланцюжок скомпрометовано, якщо guard і exit — вузли порушника
(тоді можлива кореляція кінцевих точок, 4.2). Спостерігаються також «guard порушника» — бачить клієнта
(достатньо для website fingerprinting, 4.3).

Політики вибору вхідного вузла:
  tor049  — сучасний Tor (guard-spec): 3 первинні guard, використовується перший доступний;
            строк життя guard 108–120 діб; вузол, якого немає в консенсусі > 20 діб, замінюється;
  legacy3 — Tor до 0.2.4: 3 guard, кожен ланцюжок — випадковий із доступних, строк 30–60 діб;
  noguard — новий вхідний вузол для кожного ланцюжка (як у стенді дослідження 1).

Використання: python3 simulate_tor.py <consensus_6h.pkl> <папка результатів>"""
import csv
import pickle
import sys
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEED = 2026
N_USERS = 10_000
CIRC_PER_PERIOD = 3          # ≈ 12 ланцюжків на добу (≈ 2 год активності, ланцюжок живе 10 хв)
PERIOD_DAYS = 0.25           # консенсус кожні 6 год
POLICIES = ("tor049", "legacy3", "noguard")
FRACTIONS = (0.01, 0.05, 0.10, 0.20)


def load(path):
    d = pickle.load(open(path, "rb"))
    T, R = len(d["periods"]), d["n_relays"]
    wg = np.zeros((T, R), np.float32)      # вага на позиції guard
    we = np.zeros((T, R), np.float32)      # вага на позиції exit
    for t, p in enumerate(d["periods"]):
        ids, bw = np.array(p["id"]), np.array(p["bw"], np.float32)
        g, e, W = np.array(p["guard"]), np.array(p["exit"]), p["W"]
        both = g & e
        wg[t, ids] = np.where(g, bw * np.where(both, W["Wgd"], W["Wgg"]) / 1e4, 0)
        we[t, ids] = np.where(e, bw * np.where(both, W["Wed"], W["Wee"]) / 1e4, 0)
    return d["periods"], wg, we


class Sampler:
    """Вибір guard з урахуванням вузла порушника (індекс ADV = R)."""

    def __init__(self, wg, f_g, rng):
        self.rng, self.R = rng, wg.shape[1]
        p = wg / wg.sum(axis=1, keepdims=True) * (1 - f_g)
        self.p = np.concatenate([p, np.full((len(wg), 1), f_g, np.float32)], axis=1).astype(np.float64)
        self.p /= self.p.sum(axis=1, keepdims=True)
        self.cdf = np.cumsum(self.p, axis=1)

    def draw(self, t, n):
        return np.minimum(np.searchsorted(self.cdf[t], self.rng.random(n)), self.R)


def dedupe(guards, fresh, s, t):
    """Tor не бере той самий вузол двічі: щойно обраний guard, що збігся з іншим, обирається знову."""
    for _ in range(100):
        dup = np.zeros_like(fresh)
        for j in range(guards.shape[1]):
            others = np.delete(guards, j, axis=1)
            dup[:, j] = fresh[:, j] & (others == guards[:, [j]]).any(axis=1)
        if not dup.any():
            return
        u, j = np.nonzero(dup)
        guards[u, j] = s.draw(t, len(u))


def simulate(policy, wg, f_g, f_e, rng):
    T, R = wg.shape
    ADV = R
    listed = np.concatenate([wg > 0, np.ones((T, 1), bool)], axis=1)   # вузол порушника завжди в мережі
    s = Sampler(wg, f_g, rng)
    first_comp = np.full(N_USERS, np.inf)       # день першого скомпрометованого ланцюжка
    first_guard = np.full(N_USERS, np.inf)      # день, коли клієнт уперше пішов через guard порушника
    n_comp = np.zeros(N_USERS, np.int64)
    users = np.arange(N_USERS)

    if policy != "noguard":
        k = 3
        life = (108, 120) if policy == "tor049" else (30, 60)
        guards = np.stack([s.draw(0, N_USERS) for _ in range(k)], axis=1)
        dedupe(guards, np.ones_like(guards, bool), s, 0)
        expires = rng.uniform(*life, (N_USERS, k)) / PERIOD_DAYS
        rank = np.tile(np.arange(k), (N_USERS, 1)).astype(float)
        unlisted = np.zeros((N_USERS, k))

    for t in range(T):
        day = t * PERIOD_DAYS
        if policy == "noguard":
            adv_guard_circ = rng.binomial(CIRC_PER_PERIOD, f_g, N_USERS)
        else:
            ok = listed[t][guards]
            unlisted = np.where(ok, 0, unlisted + 1)
            replace = (t >= expires) | (unlisted > 20 / PERIOD_DAYS)
            if replace.any():
                u, j = np.nonzero(replace)
                guards[u, j] = s.draw(t, len(u))
                dedupe(guards, replace, s, t)
                expires[u, j] = t + rng.uniform(*life, len(u)) / PERIOD_DAYS
                rank[u, j] = rank[u].max(axis=1) + 1          # новий guard — у кінець списку
                unlisted[u, j] = 0
                ok = listed[t][guards]
            if policy == "tor049":
                active = guards[users, np.where(ok, rank, np.inf).argmin(axis=1)]
                adv_guard_circ = np.where(active == ADV, CIRC_PER_PERIOD, 0)
            else:
                n_ok = ok.sum(axis=1)
                share = np.where(n_ok > 0, ((guards == ADV) & ok).sum(axis=1) / np.maximum(n_ok, 1), 0)
                adv_guard_circ = rng.binomial(CIRC_PER_PERIOD, share)
        comp = rng.binomial(adv_guard_circ, f_e)
        n_comp += comp
        first_comp = np.where((comp > 0) & np.isinf(first_comp), day, first_comp)
        first_guard = np.where((adv_guard_circ > 0) & np.isinf(first_guard), day, first_guard)
    return first_comp, first_guard, n_comp


def wilson(k, n, z=1.96):
    p = k / n
    c = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    return centre - c, centre + c


def main():
    periods, wg, we = load(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    T = len(periods)
    days = np.arange(T) * PERIOD_DAYS
    print(f"періодів {T} ({periods[0]['time']} … {periods[-1]['time']}), {days[-1]:.0f} діб; "
          f"користувачів {N_USERS}, ланцюжків за 6 год {CIRC_PER_PERIOD}")

    rows, curves = [], {}
    rng = np.random.default_rng(SEED)
    for f in FRACTIONS:
        for policy in POLICIES:
            fc, fg, nc = simulate(policy, wg, f, f, rng)
            curves[(policy, f)] = (fc, fg)
            for horizon in (7, 30, 90, 177):
                k = int((fc <= horizon).sum())
                lo, hi = wilson(k, N_USERS)
                kg = int((fg <= horizon).sum())
                rows.append({"policy": policy, "f": f, "days": horizon,
                             "p_compromised": k / N_USERS, "ci_low": lo, "ci_high": hi,
                             "p_adv_guard": kg / N_USERS,
                             "median_days_to_compromise": float(np.median(fc)) if k > N_USERS / 2 else None,
                             "mean_compromised_circuits": float(nc.mean())})
            r = rows[-1]
            print(f"f={f:.2f} {policy:8}: P(компрометація за 177 діб)={r['p_compromised']:.3f} "
                  f"[{r['ci_low']:.3f}; {r['ci_high']:.3f}], P(guard порушника)={r['p_adv_guard']:.3f}, "
                  f"медіана до компрометації={r['median_days_to_compromise']}, "
                  f"сер. скомпр. ланцюжків={r['mean_compromised_circuits']:.1f}")

    with open(out / "tor_mc_summary.csv", "w", newline="") as fcsv:
        w = csv.DictWriter(fcsv, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    names = {"tor049": "Tor 0.4.x (1 активний guard)", "legacy3": "3 guard (до 0.2.4)",
             "noguard": "без guard (новий вузол щоразу)"}
    fig, axes = plt.subplots(1, len(FRACTIONS), figsize=(16, 4.2), sharey=True)
    for ax, f in zip(axes, FRACTIONS):
        for policy in POLICIES:
            fc, _ = curves[(policy, f)]
            ax.plot(days, [(fc <= d).mean() for d in days], label=names[policy])
        ax.set_title(f"частка порушника f = {f:.0%}")
        ax.set_xlabel("доба")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("частка скомпрометованих користувачів")
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "tor_mc_compromise.png", dpi=150)

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for policy in POLICIES:
        _, fg = curves[(policy, 0.05)]
        ax.plot(days, [(fg <= d).mean() for d in days], label=names[policy])
    ax.set_xlabel("доба")
    ax.set_ylabel("частка користувачів")
    ax.set_title("Клієнт хоча б раз пройшов через guard порушника (f = 5 %)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "tor_mc_adv_guard.png", dpi=150)

    # мережа: скільки guard-вузлів і частка ваги найбільших (концентрація)
    g_last = np.sort(wg[-1][wg[-1] > 0])[::-1]
    e_last = np.sort(we[-1][we[-1] > 0])[::-1]
    print(f"останній консенсус: guard {len(g_last)}, top-10 guard = {g_last[:10].sum() / g_last.sum():.1%} ваги; "
          f"exit {len(e_last)}, top-10 exit = {e_last[:10].sum() / e_last.sum():.1%} ваги")
    tenure = (wg > 0).sum(axis=0)
    guards_ever = tenure > 0
    print(f"guard-вузлів за весь період: {guards_ever.sum()}, присутні > 90 % часу: "
          f"{(tenure[guards_ever] > 0.9 * T).sum()}")


if __name__ == "__main__":
    main()
