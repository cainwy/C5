"""Fig. 3: proof organisation. B1 issues one proof per output coordinate, B2
keeps a single proof over the output vector (= our scheme).

Reads data/fig3/fig3_proof_organization.json.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt

from common import NAVY, ORANGE, LABELS, clean, read_json, save, setup

MODE = {"B1 (per coordinate)": ("B1", ORANGE), "B2 (single proof)": ("B2", NAVY)}


def load(path):
    doc = read_json(path)
    out = {}
    for r in doc.get("rows", []):
        tag = MODE.get(r.get("mode"))
        if tag is None:
            continue
        out[(tag[0], int(r["l"]))] = r
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/fig3/fig3_proof_organization.json")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--lang", choices=["en", "zh"], default="en")
    args = ap.parse_args()

    setup(args.lang)
    L = LABELS[args.lang]
    rows = load(args.data)
    ls = sorted({l for (_, l) in rows})
    if not ls:
        raise SystemExit("fig3: no rows found")

    fig, axs = plt.subplots(1, 2, figsize=(3.4, 2.38))
    width = .34
    pos = list(range(len(ls)))
    for ax, field, ylab in zip(axs, ("constraints_total", "proof_bytes_total"),
                               (L["fig3_a_y"], L["fig3_b_y"])):
        for j, (tag, color) in enumerate((("B1", ORANGE), ("B2", NAVY))):
            vals = []
            for l in ls:
                if (tag, l) not in rows:
                    raise SystemExit(f"fig3: missing {tag} L={l}")
                v = float(rows[(tag, l)][field])
                vals.append(v / 1e6 if field == "constraints_total" else v)
            ax.bar([p + (j - .5) * width for p in pos], vals, width, color=color,
                   label=L["fig3_legend"][j], zorder=3)
            for p, v in zip([p + (j - .5) * width for p in pos], vals):
                ax.annotate(f"{v:.2f}" if field == "constraints_total" else f"{v:.0f}",
                            (p, v), xytext=(0, 2), textcoords="offset points",
                            fontsize=5.8, ha="center")
        ax.set_xticks(pos, [str(l) for l in ls])
        ax.set_xlabel(L["fig3_x"], labelpad=1)
        ax.set_ylabel(ylab, labelpad=1)
        clean(ax)
    axs[0].text(.03, .97, "(a)", transform=axs[0].transAxes, ha="left", va="top",
                fontweight="bold", fontsize=7.5)
    axs[1].text(.03, .97, "(b)", transform=axs[1].transAxes, ha="left", va="top",
                fontweight="bold", fontsize=7.5)
    h, lab = axs[0].get_legend_handles_labels()
    fig.legend(h, lab, frameon=False, loc="upper center", bbox_to_anchor=(.52, .995),
               ncol=2, handlelength=1.0, fontsize=7.0)
    fig.subplots_adjust(left=.15, right=.98, top=.83, bottom=.19, wspace=.5)
    save(fig, Path(args.out) / args.lang, "Fig3")


if __name__ == "__main__":
    main()
