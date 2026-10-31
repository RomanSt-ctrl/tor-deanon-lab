#!/usr/bin/env python3
"""Збір трас для website fingerprinting (4.3).
Кожне відвідування: новий ланцюжок Tor (SIGNAL NEWNYM), новий профіль Firefox (без кешу),
окремий pcap лише на час завантаження сторінки. Guard протягом прогону той самий (як у реальному Tor).
Відстежувані класи: 20 сторінок нашого onion-сервісу + 6 публічних onion-сайтів;
невідстежувані (відкритий світ): звичайні сайти і випадкові статті Вікіпедії через Tor.
Використання: wf_client.py --vm N --onion ADDR --reps 16"""
import argparse
import json
import random
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

LAB = Path("/opt/lab")
OUT = LAB / "wf"
TORRC = "SocksPort 9050\nControlPort 9051\nCookieAuthentication 0\nDataDirectory /tmp/tor-wf\nLog notice file /tmp/tor-wf.log\n"
PUBLIC = ["ddg", "torproject", "bbc", "debian", "dw", "archive"]       # у порядку рядків onion.txt
TEMPLATE = Path("/tmp/ff-template")
VISIT_PROFILE = Path("/tmp/ff-visit")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def newnym():
    """Новий ланцюжок для наступних з'єднань (Tor дозволяє не частіше ніж раз на 10 с)."""
    with socket.create_connection(("127.0.0.1", 9051)) as s:
        s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
        return s.recv(1024).decode().count("250 OK") >= 2


def browser(profile):
    opts = Options()
    opts.add_argument("-profile")
    opts.add_argument(str(profile))
    opts.add_argument("-headless")
    opts.binary_location = "/usr/bin/firefox"
    prefs = {"datareporting.healthreport.uploadEnabled": False, "datareporting.policy.dataSubmissionEnabled": False,
             "toolkit.telemetry.enabled": False, "app.normandy.enabled": False, "app.update.auto": False,
             "browser.safebrowsing.malware.enabled": False, "browser.safebrowsing.phishing.enabled": False,
             "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
             "network.trr.mode": 5, "network.proxy.type": 1, "network.proxy.socks": "127.0.0.1",
             "network.proxy.socks_port": 9050, "network.proxy.socks_version": 5,
             "network.proxy.socks_remote_dns": True,
             # фонові завантаження нового профілю (виміряно: 8,3 МБ за перші 8 с) — вимкнено, як у Tor Browser
             "services.settings.server": "http://127.0.0.1:9/v1",      # Remote Settings (localhost — не через проксі)
             "media.gmp-manager.updateEnabled": False, "media.gmp-gmpopenh264.enabled": False,
             "media.gmp-gmpopenh264.autoupdate": False, "media.gmp-widevinecdm.enabled": False,
             "extensions.update.enabled": False, "extensions.systemAddon.update.enabled": False,
             "extensions.getAddons.cache.enabled": False, "browser.region.update.enabled": False,
             "browser.search.update": False, "network.prefetch-next": False, "network.dns.disablePrefetch": True,
             "network.http.speculative-parallel-limit": 0, "browser.places.speculativeConnect.enabled": False}
    for k, v in prefs.items():
        opts.set_preference(k, v)
    d = webdriver.Firefox(options=opts, service=Service("/usr/local/bin/geckodriver"))
    d.set_page_load_timeout(60)
    return d


def make_template():
    """Новий профіль Firefox при першому старті завантажує службові дані (Remote Settings, кодек OpenH264;
    виміряно 8,3 МБ за 8 с; у релізній збірці prefs цього не вимикають). Шаблон робить це один раз;
    кожне відвідування стартує з його копії — без фонового трафіку і без кешу сайтів."""
    shutil.rmtree(TEMPLATE, ignore_errors=True)
    TEMPLATE.mkdir()
    d = browser(TEMPLATE)
    d.get("about:blank")
    time.sleep(40)
    d.quit()


def fresh_profile():
    shutil.rmtree(VISIT_PROFILE, ignore_errors=True)
    shutil.copytree(TEMPLATE, VISIT_PROFILE, ignore=shutil.ignore_patterns("lock", ".parentlock", "parent.lock"))
    return VISIT_PROFILE


def plan(args, rng):
    onion_public = [l.strip() for l in open(LAB / "sites" / "onion.txt") if l.strip()]
    clearnet = [l.strip() for l in open(LAB / "sites" / "clearnet.txt")
                if l.strip() and "wikipedia.org" not in l]                 # випадкові статті — окремо нижче
    visits = [(f"own_p{i:02d}", f"http://{args.onion}/p{i:02d}.html") for i in range(1, 21)] * args.reps
    visits += list(zip([f"pub_{n}" for n in PUBLIC], onion_public)) * args.reps
    visits += [(f"unmon_{urlsplit(u).netloc}", u) for u in clearnet] * 2
    visits += [("unmon_wiki", rng.choice(["https://en.wikipedia.org/wiki/Special:Random",
                                          "https://uk.wikipedia.org/wiki/Special:Random"])) for _ in range(40)]
    rng.shuffle(visits)
    return visits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm", type=int, required=True)
    ap.add_argument("--onion", required=True)
    ap.add_argument("--reps", type=int, default=16)
    ap.add_argument("--start", type=int, default=1, help="продовжити план з цього відвідування (після збою)")
    args = ap.parse_args()
    rng = random.Random(4300 + args.vm)
    OUT.mkdir(exist_ok=True)
    visits = plan(args, rng)
    route = run(["ip", "-o", "route", "show", "default"]).stdout.split()
    gateway, iface = route[2], route[4]

    Path("/tmp/torrc-wf").write_text(TORRC)
    Path("/tmp/tor-wf.log").unlink(missing_ok=True)          # старий лог уже містить «Bootstrapped 100%»
    tor = subprocess.Popen(["tor", "-f", "/tmp/torrc-wf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while not Path("/tmp/tor-wf.log").exists() or "Bootstrapped 100%" not in Path("/tmp/tor-wf.log").read_text():
        time.sleep(1)
    make_template()
    print(f"vm{args.vm}: {len(visits)} відвідувань", flush=True)

    last_nym = 0.0
    with open(OUT / f"visits{args.vm}.jsonl", "a") as log:
        for i, (label, url) in enumerate(visits, 1):
            if i < args.start:
                continue
            rec = {"vm": args.vm, "i": i, "label": label, "url": url}
            time.sleep(max(0, last_nym + 10.5 - time.time()))
            rec["newnym"] = newnym()
            last_nym = time.time()
            pcap = OUT / f"{label}__vm{args.vm}_i{i:04d}.pcap"
            d = None
            try:
                d = browser(fresh_profile())
                d.get("about:blank")
                time.sleep(2)                                  # фоновий старт Firefox — до запису
                cap = subprocess.Popen(["sudo", "tcpdump", "-i", iface, "-n", "-Z", "lab", "-w", str(pcap),
                                        f"tcp and not (host {gateway} and port 22)"], stderr=subprocess.DEVNULL)
                time.sleep(1)
                t0 = time.time()
                try:
                    d.get(url)
                    rec["status"] = "ok"
                except Exception as e:
                    rec["status"] = f"timeout: {type(e).__name__}"
                rec["load_s"] = round(time.time() - t0, 2)
                time.sleep(3)                                  # догрузка після події load
                rec["title"] = (d.title or "")[:80]
            except Exception as e:                             # збій браузера — траса не годиться
                rec["status"] = f"error: {type(e).__name__}"
                rec.setdefault("load_s", 0)
            finally:
                run(["sudo", "pkill", "-INT", "-x", "tcpdump"])
                time.sleep(0.5)
                try:
                    d and d.quit()
                except Exception:
                    run(["pkill", "-x", "firefox"])
            rec["bytes"] = pcap.stat().st_size if pcap.exists() else 0
            log.write(json.dumps(rec, ensure_ascii=False) + "\n")
            log.flush()
            print(f"[{i}/{len(visits)}] {label:28} {rec['status']:8} {rec['load_s']:6} с", flush=True)
    tor.terminate()
    print("готово", flush=True)


if __name__ == "__main__":
    main()
