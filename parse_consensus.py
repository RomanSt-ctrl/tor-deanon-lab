#!/usr/bin/env python3
"""Зводить консенсуси Tor (CollecTor) у компактний файл для імітаційної моделі 4.1.
Береться кожен консенсус о 00, 06, 12, 18 год UTC. Для кожного вузла: індекс fingerprint,
вага (w Bandwidth=), чи може бути guard, чи може бути exit для порту 443.
Використання: python3 parse_consensus.py <папка з консенсусами> <вихідний .pkl>"""
import pickle
import sys
from multiprocessing import Pool
from pathlib import Path

HOURS = ("-00-00-00-", "-06-00-00-", "-12-00-00-", "-18-00-00-")


def allows(policy, port):
    """Стисла політика виходу з рядка 'p': 'accept 80,443,1000-2000' або 'reject 1-65535'."""
    action, ranges = policy.split()
    inside = any(int(a) <= port <= int(b or a)
                 for a, _, b in (r.partition("-") for r in ranges.split(",")))
    return inside == (action == "accept")


def parse(path):
    relays, weights = [], {}
    fp = flags = bw = None
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("r "):
            fp = line.split()[2]
        elif line.startswith("s "):
            flags = set(line.split()[1:])
        elif line.startswith("w "):
            bw = int(line.split("Bandwidth=")[1].split()[0])
        elif line.startswith("p "):
            ok = "BadExit" not in flags and "Valid" in flags and "Running" in flags
            guard = ok and "Guard" in flags and "Fast" in flags and "Stable" in flags
            exit_ = ok and "Exit" in flags and allows(line[2:].strip(), 443)
            relays.append((fp, bw, guard, exit_))
        elif line.startswith("bandwidth-weights"):
            weights = {k: int(v) for k, v in (kv.split("=") for kv in line.split()[1:])}
    return path.name[:13], relays, weights          # '2026-10-24-12'


def main():
    files = sorted(p for p in Path(sys.argv[1]).rglob("*-consensus") if any(h in p.name for h in HOURS))
    with Pool() as pool:
        data = pool.map(parse, files, chunksize=8)
    index = {}
    periods = []
    for stamp, relays, weights in data:
        ids = [index.setdefault(fp, len(index)) for fp, *_ in relays]
        periods.append({"time": stamp, "id": ids,
                        "bw": [r[1] for r in relays], "guard": [r[2] for r in relays],
                        "exit": [r[3] for r in relays], "W": weights})
    pickle.dump({"periods": periods, "n_relays": len(index)}, open(sys.argv[2], "wb"))
    print(f"консенсусів: {len(periods)} ({periods[0]['time']} … {periods[-1]['time']}), "
          f"унікальних вузлів: {len(index)}")
    for p in (periods[0], periods[-1]):
        print(f"  {p['time']}: вузлів {len(p['id'])}, guard {sum(p['guard'])}, exit:443 {sum(p['exit'])}, "
              f"Wgg={p['W'].get('Wgg')} Wgd={p['W'].get('Wgd')} Wee={p['W'].get('Wee')} Wed={p['W'].get('Wed')}")


if __name__ == "__main__":
    main()
