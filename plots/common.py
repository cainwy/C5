"""Shared plotting helpers: fonts, colours, CSV/JSON reading, output."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

NAVY = "#246A91"
ORANGE = "#D97936"
SLATE = "#778597"
GREEN = "#32845B"
INK = "#283039"

CJK_FONTS = [r"C:\Windows\Fonts\simhei.ttf", r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simsun.ttc"]

LABELS = {
    "en": {
        "our": "Our",
        "gai": "Gai",
        "gai_bits": "Gai ({bits})",
        "fig1_metrics": ["Proof\nverification", "Chaincode\nverification"],
        "fig1_y": "Time (ms)",
        "fig1_legend": ["Our", "Gai (1024)", "Gai (3072)"],
        "fig2_x": "Servers $n$",
        "fig2_y": "Recovery time (ms)",
        "fig3_x": "$L$",
        "fig3_a_y": "Constraints (M)",
        "fig3_b_y": "Proof bytes (B)",
        "fig3_legend": ["B1 (per coordinate)", "Our / B2 (single proof)"],
        "fig4_x": "Output dimension $L$",
        "fig4_y": "Recovery time (ms)",
        "fig5_x": "Output dimension $L$",
        "fig5_y": "Delivery volume (B)",
    },
    "zh": {
        "our": "本方案",
        "gai": "Gai",
        "gai_bits": "Gai（{bits}）",
        "fig1_metrics": ["证明验证", "链码验证"],
        "fig1_y": "时间（ms）",
        "fig1_legend": ["本方案", "Gai（1024）", "Gai（3072）"],
        "fig2_x": "服务器数 $n$",
        "fig2_y": "恢复时间（ms）",
        "fig3_x": "$L$",
        "fig3_a_y": "约束数（百万）",
        "fig3_b_y": "证明大小（字节）",
        "fig3_legend": ["B1（逐坐标）", "本方案 / B2（单证明）"],
        "fig4_x": "输出维度 $L$",
        "fig4_y": "恢复时间（ms）",
        "fig5_x": "输出维度 $L$",
        "fig5_y": "交付量（字节）",
    },
}


def setup(lang: str) -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8, "axes.labelsize": 8.5, "xtick.labelsize": 7.6,
        "ytick.labelsize": 7.6, "legend.fontsize": 7.2,
        "axes.linewidth": .65, "axes.edgecolor": INK,
        "xtick.direction": "out", "ytick.direction": "out",
        "pdf.fonttype": 42, "ps.fonttype": 42,
        "figure.facecolor": "white", "savefig.facecolor": "white",
        "axes.unicode_minus": False,
    })
    if lang == "zh":
        for p in CJK_FONTS:
            if os.path.exists(p):
                font_manager.fontManager.addfont(p)
                name = font_manager.FontProperties(fname=p).get_name()
                plt.rcParams["font.family"] = [name, "DejaVu Sans"]
                break


def clean(ax) -> None:
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="both", width=.6, length=3)
    ax.set_axisbelow(True)


def save(fig, outdir, stem: str) -> None:
    Path(outdir).mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "svg", "png"):
        fig.savefig(str(Path(outdir) / f"{stem}.{ext}"), dpi=300,
                    bbox_inches="tight", pad_inches=.06)
    plt.close(fig)
    print(f"wrote {outdir}/{stem}.{{pdf,svg,png}}")


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
