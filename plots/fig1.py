"""Fig. 1: proof verification and chaincode verification, three series.

Reads data/fig1a/fig1a_proof_verification.csv (off-chain, in-process) and
data/fig1b/fig1b_onchain_summary.csv (Fabric chaincode, produced by
plots/merge_fig1b.py). When the on-chain file is absent the figure falls back to
the off-chain measurement only, so the off-chain run stays usable on its own.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mt

from common import NAVY, ORANGE, SLATE, LABELS, clean, read_csv, save, setup

SERIES = ["Our", "Gai (1024)", "Gai (3072)"]
COLOR = {"Our": NAVY, "Gai (1024)": SLATE, "Gai (3072)": ORANGE}
PROFILE = {"Our": "C5", "Gai (1024)": "Gai(1024)", "Gai (3072)": "Gai(3072)"}


def off_chain(path):
    rows = read_csv(path)
    out = {}
    for r in rows:
        if r["metric"] != "proof_verification":
            continue
        for s, prof in PROFILE.items():
            if r["profile"] == prof:
                out[s] = float(r["median_ms"])
    return out


def on_chain(path):
    rows = read_csv(path)
    out = {}
    for r in rows:
        for s, prof in PROFILE.items():
            if r["profile"] == prof:
                out[s] = float(r["cc_core_ms"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--off-chain", default="data/fig1a/fig1a_proof_verification.csv")
    ap.add_argument("--on-chain", default="data/fig1b/fig1b_onchain_summary.csv")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--lang", choices=["en", "zh"], default="en")
    args = ap.parse_args()

    setup(args.lang)
    L = LABELS[args.lang]
    off = off_chain(args.off_chain)
    onc = on_chain(args.on_chain) if Path(args.on_chain).exists() else {}

    fig, ax = plt.subplots(figsize=(3.5, 2.35))
    width = .25
    for j, s in enumerate(SERIES):
        vals = [off.get(s, 0.0), onc.get(s, 0.0)]
        bs = ax.bar([0 + (j - 1) * width, 1 + (j - 1) * width], vals, width,
                    color=COLOR[s], label=L["fig1_legend"][j], zorder=3)
        for b, v in zip(bs, vals):
            if v <= 0:
                continue
            ax.annotate(f"{v:.3f}", (b.get_x() + b.get_width() / 2, v),
                        xytext=(0, 2.5), textcoords="offset points",
                        fontsize=6.6, ha="center")
    ax.set_yscale("log")
    ax.set_ylim(3, 2000)
    ax.set_yticks([5, 10, 20, 50, 100, 200, 500, 1000])
    ax.yaxis.set_major_formatter(mt.ScalarFormatter())
    ax.yaxis.set_minor_locator(mt.NullLocator())
    ax.set_ylabel(L["fig1_y"])
    ax.set_xticks([0, 1], L["fig1_metrics"])
    ax.legend(loc="lower center", frameon=False, ncol=3, handlelength=1,
              columnspacing=.8, bbox_to_anchor=(.50, 1.01), fontsize=6.8)
    clean(ax)
    fig.subplots_adjust(left=.17, right=.985, bottom=.24, top=.82)
    save(fig, Path(args.out) / args.lang, "Fig1")


if __name__ == "__main__":
    main()
