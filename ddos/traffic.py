"""Packet-level traffic simulation.

Produces one row per packet with the fields a capture gives you (timestamp, source
address, protocol, TCP flags, destination port, size), with a ground-truth label for
evaluation. The scenario mixes normal traffic with a legitimate flash crowd and three
attacks:

* flash crowd: four times the usual traffic from many new, real users (a sale, a result
  announcement). Not an attack, and the classic false positive of rate thresholds.
* SYN flood: half-open TCP connections from spoofed, random source addresses.
* UDP flood: large UDP datagrams to random ports from a few hundred bots.
* HTTP flood: a botnet completing TCP handshakes and requesting pages, each bot far
  faster than any person.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd

COLUMNS = ["ts", "src", "proto", "flags", "dport", "size", "label"]


@dataclass
class Episode:
    kind: str           # flash_crowd | syn_flood | udp_flood | http_flood
    start: float
    end: float
    pps: float          # packets per second
    bots: int = 60      # http_flood: number of attacking clients


SCENARIO = [Episode("flash_crowd", 150, 210, 1200), Episode("syn_flood", 270, 330, 6000),
            Episode("udp_flood", 390, 430, 4000), Episode("http_flood", 480, 540, 1500)]
# Attacks barely above normal traffic (300 packets/s).
LOW_RATE = [Episode("flash_crowd", 150, 210, 600), Episode("syn_flood", 270, 330, 500),
            Episode("udp_flood", 390, 430, 350), Episode("http_flood", 480, 540, 300)]
# The known blind spot: an HTTP flood from 3,000 bots, each as slow as a person, looks
# exactly like a flash crowd at the network level.
MIMICRY = [Episode("flash_crowd", 150, 210, 1200),
           Episode("http_flood", 330, 390, 1200, bots=3000)]
SCENARIOS = {"standard": SCENARIO, "low_rate": LOW_RATE, "mimicry": MIMICRY}


def _ips(rng, n, first_octets=(10, 250)) -> np.ndarray:
    a = rng.integers(*first_octets, n)
    rest = rng.integers(0, 256, (n, 3))
    return np.array([f"{x}.{b}.{c}.{d}" for x, (b, c, d) in zip(a, rest)])


def _web_packets(rng, ts, srcs, label) -> pd.DataFrame:
    """Ordinary TCP web traffic: a SYN for every ~12 packets, the rest ACK/PSH data."""
    n = len(ts)
    flags = rng.choice(["S", "A", "PA", "FA"], n, p=[0.08, 0.52, 0.36, 0.04])
    size = np.where(flags == "PA", rng.integers(300, 1460, n), rng.integers(40, 80, n))
    return pd.DataFrame({"ts": ts, "src": srcs, "proto": "TCP", "flags": flags,
                         "dport": rng.choice([80, 443], n, p=[0.2, 0.8]), "size": size,
                         "label": label})


def normal(rng, duration, pps=300, clients=2500) -> pd.DataFrame:
    n = rng.poisson(pps * duration)
    ts = np.sort(rng.uniform(0, duration, n))
    pool = _ips(rng, clients)
    weights = 1 / np.arange(1, clients + 1) ** 0.9            # a few heavy users (Zipf)
    srcs = pool[rng.choice(clients, n, p=weights / weights.sum())]
    web = _web_packets(rng, ts, srcs, "normal")
    dns = rng.random(n) < 0.1                                    # some DNS over UDP
    web.loc[dns, ["proto", "flags", "dport"]] = ["UDP", "", 53]
    web.loc[dns, "size"] = rng.integers(60, 200, dns.sum())
    return web


def episode(rng, e: Episode) -> pd.DataFrame:
    n = rng.poisson(e.pps * (e.end - e.start))
    ts = np.sort(rng.uniform(e.start, e.end, n))
    label = "normal" if e.kind == "flash_crowd" else e.kind
    if e.kind == "flash_crowd":          # many new users, a few dozen packets each
        return _web_packets(rng, ts, _ips(rng, max(n // 25, 1))[rng.integers(0, max(n // 25, 1), n)],
                            label)
    if e.kind == "syn_flood":            # every packet a SYN from a fresh spoofed address
        return pd.DataFrame({"ts": ts, "src": _ips(rng, n, (1, 224)), "proto": "TCP",
                             "flags": "S", "dport": 443, "size": 60, "label": label})
    if e.kind == "udp_flood":
        bots = _ips(rng, 300)
        return pd.DataFrame({"ts": ts, "src": bots[rng.integers(0, 300, n)], "proto": "UDP",
                             "flags": "", "dport": rng.integers(1024, 65535, n),
                             "size": rng.integers(1000, 1472, n), "label": label})
    bots = _ips(rng, e.bots)             # http_flood: by default few sources, each very busy
    return _web_packets(rng, ts, bots[rng.integers(0, e.bots, n)], label)


def simulate(duration: int = 600, seed: int = 3, scenario=SCENARIO) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = [normal(rng, duration)] + [episode(rng, e) for e in scenario]
    return pd.concat(parts).sort_values("ts", kind="stable").reset_index(drop=True)
