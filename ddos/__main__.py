"""python -m ddos demo                 # simulate the scenarios, detect, write out/report.html
python -m ddos analyze packets.csv   # detect on your own packets (columns: ts, src, proto,
                                     # flags, dport, size; ts in seconds)"""
import json
import sys
from pathlib import Path

import pandas as pd

from ddos import report
from ddos.detect import detect, evaluate, incidents, windows
from ddos.traffic import SCENARIOS, simulate

OUT = Path("out")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    if sys.argv[1:2] == ["demo"]:
        results, standard = {}, None
        for name, scenario in SCENARIOS.items():
            packets = simulate(seed=3, scenario=scenario)
            w = detect(windows(packets))
            results[name] = evaluate(w)
            if name == "standard":
                standard = (w, len(packets))
            print(name, json.dumps(results[name]))
        (OUT / "report.html").write_text(report.render(*standard, results), encoding="utf-8")
        (OUT / "metrics.json").write_text(json.dumps(results, indent=1))
    elif sys.argv[1:2] == ["analyze"] and len(sys.argv) == 3:
        w = detect(windows(pd.read_csv(sys.argv[2], keep_default_na=False)))
        for i in incidents(w):
            print(i)
    else:
        sys.exit(__doc__)
    print(f"Report: {OUT / 'report.html'}" if sys.argv[1] == "demo" else "")


if __name__ == "__main__":
    main()
