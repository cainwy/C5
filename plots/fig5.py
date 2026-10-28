"""Fig. 5: authenticated recovery-delivery volume across output dimensions.

Reads data/fig5/fig5_delivery_volume.json. Each point is the number of bytes a
receiver must obtain to hold t=f+1 authenticated deliveries.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mt

from common import NAVY, ORANGE, GREEN, LABELS, clean, read_json, save, setup

CFG = {(3, 1): (NAVY, "o"), (5, 2): (ORANGE, "s"), (9, 4): (GREEN, "^")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/fig5/fig5_delivery_volume.json")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--lang", choices=["en", "zh"], default="en")
    args = ap.parse_args()

    setup(args.lang)
    L = LABELS[args.lang]
    doc = read_json(args.data)
    pts = {}
    for p in doc["points"]:
        key = (int(p["n"]), int(p["f"]), int(p["l"]))
        if "delivery_bytes" in p:
            pts[key] = float(p["delivery_bytes"])
        elif "bytes" in p:
            pts[key] = float(p["bytes"])
    if not pts:
        raise SystemExit("fig5: no byte fields found")
    ls = sorted({l for (_, _, l) in pts})
    pos = list(range(len(ls)))

    fig, ax = plt.subplots(figsize=(3.4, 2.48))
    for (n, f), (color, mark) in CFG.items():
        y = []
        for l in ls:
            if (n, f, l) not in pts:
                raise SystemExit(f"fig5: missing ({n},{f}) L={l}")
            y.append(pts[(n, f, l)])
        ax.plot(pos, y, lw=1.35, marker=mark, ms=3.8, color=color, label=f"$({n},{f})$")
    ax.set_yscale("log")
    ax.set_xticks(pos, [str(l) for l in ls])
    ax.set_xlabel(L["fig5_x"], labelpad=2)
    ax.set_ylabel(L["fig5_y"], labelpad=2)
    ax.yaxis.set_major_formatter(mt.ScalarFormatter())
    ax.legend(frameon=False, loc="upper left", ncol=3, columnspacing=.85,
              handlelength=1.1, handletextpad=.32, bbox_to_anchor=(-.01, 1.03))
    clean(ax)
    fig.subplots_adjust(left=.175, right=.98, bottom=.21, top=.86)
    save(fig, Path(args.out) / args.lang, "Fig5")


if __name__ == "__main__":
    main()
