#!/usr/bin/env python3
"""Журнал подій CIRC_BW onion-сервісу (4.2, позиція «бачить окремі ланцюжки»).
Tor раз на секунду повідомляє для кожного активного ланцюжка, скільки байтів прочитано/записано.
Це емуляція погляду шкідливого guard або вилученого сервера — без додавання вузлів у мережу Tor.
Час t — годинник VM у момент отримання події (той самий, що в pcap).
Використання: circbw_logger.py <файл.jsonl>   (зупинка — SIGINT)"""
import json
import socket
import sys
import time

with socket.create_connection(("127.0.0.1", 9051)) as s, open(sys.argv[1], "w") as out:
    s.sendall(b'AUTHENTICATE ""\r\nSETEVENTS CIRC_BW\r\n')
    buf = b""
    try:
        while data := s.recv(65536):
            buf += data
            *lines, buf = buf.split(b"\r\n")
            t = time.time()
            for line in lines:
                if not line.startswith(b"650 CIRC_BW "):
                    continue
                kv = dict(x.split("=", 1) for x in line.decode().split()[2:])
                out.write(json.dumps({"t": t, "id": int(kv["ID"]), "read": int(kv["READ"]),
                                      "written": int(kv["WRITTEN"]), "tor_time": kv["TIME"]}) + "\n")
            out.flush()
    except KeyboardInterrupt:
        pass
