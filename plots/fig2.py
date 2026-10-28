"""Fig. 2: receiver-recovery computation versus the number of servers.

Reads data/fig2/fig2_recovery.json for our scheme and for Gai et al.'s 1024-bit
and 3072-bit configurations.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mt

from common import NAVY, ORANGE, SLATE, INK, LABELS, clean, read_json, save, setup

SERIES = ["Our", "Gai (1024)", "Gai (3072)"]
COLOR = {"Our": NAVY, "Gai (1024)": SLATE, "Gai (3072)": ORANGE}
PROFILE_PREFIX = {"Gai (1024)": 1024, "Gai (3072)": 3072}


def load(path):
    doc = read_json(path)
    out = {}
    for prof in doc.get("profiles", []):
        bits = int((prof.get("profile") or {}).get("prime_bits") or 0)
        label = next((s for s, b in PROFILE_PREFIX.items() if b == bits), None)
        for pt in prof.get("points", []):
            n = int(pt["n"])
            st = (pt.get("trials_stat") or {}).get("summary") or {}
            med = float(pt.get("total_ms_median", 0.0))
            lo = float(st.get("min", med))
            hi = float(st.get("max", med))
            if pt.get("scheme") == "C5" or label is None:
                out[("Our", n)] = (med, lo, hi)
            else:
                out[(label, n)] = (med, lo, hi)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/fig2/fig2_recovery.json")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--lang", choices=["en", "zh"], default="en")
    args = ap.parse_args()

    setup(args.lang)
    L = LABELS[args.lang]
    pts = load(args.data)
    ns = sorted({n for (_, n) in pts})
    if not ns:
        raise SystemExit("fig2: no recovery points found")

    fig, ax = plt.subplots(figsize=(3.5, 2.45))
    width = .245
    x = list(range(len(ns)))
    for j, s in enumerate(SERIES):
        y, lo, hi = [], [], []
        for n in ns:
            if (s, n) not in pts:
                raise SystemExit(f"fig2: missing {s} n={n}")
            m, a, b = pts[(s, n)]
            y.append(m)
            lo.append(max(0.0, m - a))
            hi.append(max(0.0, b - m))
        ax.bar([xx + (j - 1) * width for xx in x], y, width, color=COLOR[s],
               label=L["fig1_legend"][j], linewidth=0, zorder=3,
               yerr=[lo, hi], ecolor=INK, capsize=1.5, error_kw={"linewidth": .6})
    ax.set_yscale("log")
    ax.set_ylim(.02, 400000)
    ax.set_xticks(x, [str(n) for n in ns])
    ax.set_xlabel(L["fig2_x"], labelpad=2)
    ax.set_ylabel(L["fig2_y"], labelpad=2)
    ax.yaxis.set_major_locator(mt.LogLocator(base=10, numticks=8))
    ax.yaxis.set_minor_locator(mt.NullLocator())
    ax.yaxis.set_major_formatter(mt.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.legend(loc="upper center", bbox_to_anchor=(.50, 1.17), ncol=3, frameon=False,
              columnspacing=.8, handlelength=.85, handletextpad=.35, fontsize=6.9)
    clean(ax)
    fig.subplots_adjust(left=.18, right=.985, bottom=.19, top=.80)
    save(fig, Path(args.out) / args.lang, "Fig2")


if __name__ == "__main__":
    main()
