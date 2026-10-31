#!/usr/bin/env python3
"""Клієнт для кореляційного експерименту (4.2). Протягом заданого часу через Tor завантажує
або ресурси нашого onion-сервісу (own), або сторонні сайти (decoy), робить випадкові паузи,
пише трафік (tcpdump) і журнал подій з точним часом — це «правильні відповіді» для оцінки атаки.
Використання: corr_client.py --vm N --onion ADDR --minutes 60"""
import argparse
import json
import random
import re
import subprocess
import time
from pathlib import Path

LAB = Path("/opt/lab")
OUT = LAB / "corr"
OWN = [f"p{i:02d}.html" for i in range(1, 21)] + [f"files/f{k}k.bin" for k in (100, 300, 1000, 3000)]


CURL = ["curl", "-s", "-m", "120", "-L", "--socks5-hostname", "127.0.0.1:9050",
        "-A", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"]


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm", type=int, required=True)
    ap.add_argument("--onion", required=True)
    ap.add_argument("--minutes", type=float, default=60)
    args = ap.parse_args()
    rng = random.Random(4200 + args.vm)
    OUT.mkdir(exist_ok=True)
    decoys = [l.strip() for f in ("onion.txt", "clearnet.txt")
              for l in open(LAB / "sites" / f) if l.strip() and not l.startswith("#")]

    with open("/tmp/tor.log", "w") as log:
        tor = subprocess.Popen(["tor", "-f", str(LAB / "torrc" / "plain")], stdout=log, stderr=subprocess.STDOUT)
    while "Bootstrapped 100%" not in Path("/tmp/tor.log").read_text():
        time.sleep(1)
    route = run(["ip", "-o", "route", "show", "default"]).stdout.split()
    gateway, iface = route[2], route[4]
    cap = subprocess.Popen(["sudo", "tcpdump", "-i", iface, "-n", "-Z", "lab", "-w", str(OUT / f"client{args.vm}.pcap"),
                            f"not (host {gateway} and tcp port 22)"], stderr=subprocess.DEVNULL)
    time.sleep(5)

    end = time.time() + args.minutes * 60
    with open(OUT / f"events{args.vm}.jsonl", "w") as ev:
        while time.time() < end:
            own = rng.random() < 0.5
            url = f"http://{args.onion}/{rng.choice(OWN)}" if own else rng.choice(decoys)
            t0 = time.time()
            r = run(CURL + ["-o", "/tmp/page", "-w", "%{http_code} %{size_download}", url])
            code, size = (r.stdout.split() + ["000", "0"])[:2]
            size = int(size)
            if own and code == "200" and url.endswith(".html"):
                # як браузер: після HTML — усі зображення і скрипти сторінки одним викликом curl (одне з'єднання)
                res = re.findall(r'src="(/[^"]+)"', open("/tmp/page", errors="replace").read())
                if res:
                    args_ = [a for path in res for a in (f"http://{args.onion}{path}", "-o", "/dev/null")]
                    r2 = run(CURL + ["-w", "%{size_download}\n"] + args_)
                    size += sum(int(x) for x in r2.stdout.split())
            t1 = time.time()
            ev.write(json.dumps({"vm": args.vm, "t0": t0, "t1": t1, "own": own, "url": url,
                                 "code": code, "bytes": size}) + "\n")
            ev.flush()
            time.sleep(rng.expovariate(1 / 20))          # пауза: в середньому 20 с

    time.sleep(5)
    run(["sudo", "pkill", "-INT", "-x", "tcpdump"])
    cap.wait()
    tor.terminate()
    print("готово")


if __name__ == "__main__":
    main()
