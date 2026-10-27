"""Detection over one-second windows.

Features per window: packets, bytes, distinct sources, normalised source entropy, share of
TCP packets that are bare SYNs (connections never completed), share of UDP, packets per
source, and the busiest source's share.

Each feature is compared with a robust baseline (median and MAD of the last BASELINE
seconds that were not flagged, so an attack cannot raise its own baseline). A volume
surge alone is reported as a surge, which a flash crowd also causes; it is called an
attack only when the make-up of the traffic changes as well:

* SYN flood: the bare-SYN share jumps (half-open connections);
* UDP flood: the UDP share jumps;
* HTTP flood: packets per source jump (a few clients far busier than any person).

The comparison is the simplest detector: a fixed threshold at mean + 3 standard
deviations of the packet rate in the first TRAINING seconds.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd

BASELINE = 60
TRAINING = 120
Z = 4.0
FEATURES = ["pkts", "bytes", "sources", "entropy", "syn_share", "udp_share", "pkts_per_src",
            "top_share"]


def windows(packets: pd.DataFrame) -> pd.DataFrame:
    p = packets.assign(sec=packets["ts"].astype(int),
                       syn=(packets["proto"] == "TCP") & (packets["flags"] == "S"),
                       tcp=packets["proto"] == "TCP", udp=packets["proto"] == "UDP")
    g = p.groupby("sec")
    out = pd.DataFrame({"pkts": g.size(), "bytes": g["size"].sum(), "sources": g["src"].nunique(),
                        "syn": g["syn"].sum(), "tcp": g["tcp"].sum(), "udp": g["udp"].sum()})
    counts = p.groupby(["sec", "src"]).size()
    def entropy(c):
        q = c.to_numpy() / c.sum()
        h = -(q * np.log2(q)).sum()
        return h / np.log2(len(q)) if len(q) > 1 else 0.0
    out["entropy"] = counts.groupby(level=0).apply(entropy)
    out["top_share"] = counts.groupby(level=0).max() / out["pkts"]
    out["syn_share"] = out["syn"] / out["tcp"].clip(lower=1)
    out["udp_share"] = out["udp"] / out["pkts"]
    out["pkts_per_src"] = out["pkts"] / out["sources"]
    if "label" in packets:                      # ground truth: the dominant attack, if any
        attack = p[p["label"] != "normal"].groupby("sec")["label"].agg(lambda s: s.mode()[0])
        share = p[p["label"] != "normal"].groupby("sec").size() / out["pkts"]
        out["truth"] = np.where(share.reindex(out.index).fillna(0) > 0.1,
                                attack.reindex(out.index).fillna("normal"), "normal")
    return out.reset_index()


def robust_z(value: float, history: np.ndarray) -> float:
    med = np.median(history)
    mad = np.median(np.abs(history - med)) * 1.4826
    return (value - med) / max(mad, 1e-6 + 0.05 * abs(med))


def detect(w: pd.DataFrame) -> pd.DataFrame:
    """Adds `z_*` scores, `verdict` (normal | surge | syn_flood | udp_flood | http_flood)."""
    w = w.copy()
    verdicts, zs, clean = [], {f: [] for f in FEATURES}, []
    for i, row in w.iterrows():
        hist = w.loc[clean[-BASELINE:], FEATURES] if len(clean) >= 10 else w.loc[:max(i - 1, 0), FEATURES]
        z = {f: robust_z(row[f], hist[f].to_numpy()) if len(hist) > 5 else 0.0 for f in FEATURES}
        for f in FEATURES:
            zs[f].append(z[f])
        verdict = "normal"
        if z["pkts"] > Z or z["bytes"] > Z:
            if z["syn_share"] > Z:
                verdict = "syn_flood"
            elif z["udp_share"] > Z:
                verdict = "udp_flood"
            elif z["pkts_per_src"] > Z:
                verdict = "http_flood"
            else:
                verdict = "surge"
        if verdict == "normal":
            clean.append(i)
        verdicts.append(verdict)
    for f in FEATURES:
        w[f"z_{f}"] = np.round(zs[f], 2)
    w["verdict"] = verdicts
    return w


def threshold_baseline(w: pd.DataFrame) -> pd.Series:
    train = w["pkts"].iloc[:TRAINING]
    return w["pkts"] > train.mean() + 3 * train.std()


@dataclass
class Incident:
    kind: str
    start: int
    end: int
    peak_pps: int
    sources: int
    top_share: float


def incidents(w: pd.DataFrame, gap: int = 3, min_seconds: int = 2) -> list[Incident]:
    """Flagged seconds of the same kind, at most `gap` apart, merged into incidents; an
    incident shorter than `min_seconds` is noise (one busy client in one second)."""
    out: list[Incident] = []
    for _, r in w[w["verdict"] != "normal"].iterrows():
        last = out[-1] if out else None
        if last and last.kind == r["verdict"] and r["sec"] - last.end <= gap:
            last.end = int(r["sec"])
            last.peak_pps = max(last.peak_pps, int(r["pkts"]))
            last.sources = max(last.sources, int(r["sources"]))
            last.top_share = max(last.top_share, float(r["top_share"]))
        else:
            out.append(Incident(r["verdict"], int(r["sec"]), int(r["sec"]), int(r["pkts"]),
                                int(r["sources"]), float(r["top_share"])))
    return [i for i in out if i.end - i.start + 1 >= min_seconds]


def evaluate(w: pd.DataFrame) -> dict:
    truth = w["truth"] != "normal"
    ours = w["verdict"].isin(["syn_flood", "udp_flood", "http_flood"])
    base = threshold_baseline(w)
    def score(pred):
        tp, fp = int((pred & truth).sum()), int((pred & ~truth).sum())
        fn = int((~pred & truth).sum())
        return {"precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
                "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
                "false_alarm_seconds": fp}
    typed = w[ours & truth]
    return {"detector": score(ours), "threshold": score(base),
            "attack_type_accuracy": round(float((typed["verdict"] == typed["truth"]).mean()), 3)
            if len(typed) else None}
