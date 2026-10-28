"""Table 1 and Fig. 1(b): merge the real-Fabric raw records into plotting tables.

Inputs (produced by run/fabric_onchain.sh):
  data/fig1b/{c5,gai1024,gai3072}/table1_{c5,gai}_raw.jsonl
  data/logs/cc_timing_*.log                chaincode-side timings by tx id

Outputs:
  data/fig1b/fig1b_onchain_tx.csv          per transaction
  data/fig1b/fig1b_onchain_summary.csv     per configuration
  data/tab1/tab1_cumulative.csv            cumulative verification-phase time
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import statistics as st
from pathlib import Path

C5 = "C5"
PROFILE_LABEL = {1024: "Gai(1024)", 3072: "Gai(3072)"}


def load_cc_log(path):
    entries = {}
    with open(path, errors="ignore") as f:
        for line in f:
            i = line.find("{")
            if i < 0:
                continue
            try:
                obj = json.loads(line[i:])
            except Exception:
                continue
            if obj.get("tag") != "cc_core_timing":
                continue
            entries.setdefault(obj.get("tx_id", ""), []).append(obj)
    return entries


def critical(entries):
    return max(entries, key=lambda e: e.get("verify_core_ns", 0)) if entries else None


def scheme_of(path):
    return C5 if "table1_c5_raw" in os.path.basename(path) else "Gai"


def profile_of(rec, scheme):
    if scheme == C5:
        return "C5"
    p = rec.get("profile", "")
    for bits in (1024, 3072):
        if f"({bits}-bit" in p:
            return PROFILE_LABEL[bits]
    return p or "Gai"


def collect(raw_root, logmap):
    tx, missing = [], 0
    for path in sorted(glob.glob(os.path.join(raw_root, "*", "table1_*_raw.jsonl"))):
        scheme = scheme_of(path)
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("phase") != "measured" or rec.get("status") != "PASS":
                    continue
                fab = rec.get("fabric") or {}
                ids = fab.get("verify_tx_ids") or []
                endorse = fab.get("verify_tx_endorsement_ns") or []
                commit = fab.get("verify_tx_commit_ns") or []
                totals = fab.get("verify_tx_total_ns") or []
                prof = profile_of(rec, scheme)
                for i, txid in enumerate(ids):
                    ent = critical(logmap.get(txid, []))
                    if ent is None:
                        missing += 1
                        continue
                    cc = ent.get("verify_core_ns", 0) / 1e6
                    if scheme == C5:
                        crypto = (ent.get("proof_verify_ns", 0)
                                  + ent.get("certificate_verify_ns", 0)
                                  + ent.get("signature_verify_ns", 0)) / 1e6
                    else:
                        crypto = (ent.get("zkpoc_verify_ns", 0)
                                  + ent.get("commitment_verify_ns", 0)
                                  + ent.get("group_check_ns", 0)) / 1e6
                    end_ms = (endorse[i] if i < len(endorse) else 0) / 1e6
                    tx.append({
                        "scheme": scheme, "profile": prof,
                        "config": rec.get("config", ""), "rep": rec.get("rep", -1),
                        "tx_id": txid,
                        "cc_core_ms": round(cc, 4),
                        "crypto_ms": round(crypto, 4),
                        "other_cc_ms": round(max(0.0, cc - crypto), 4),
                        "endorse_ms": round(end_ms, 4),
                        "transport_ms": round(max(0.0, end_ms - cc), 4),
                        "commit_ms": round((commit[i] if i < len(commit) else 0) / 1e6, 4),
                        "tx_total_ms": round((totals[i] if i < len(totals) else 0) / 1e6, 4),
                    })
    return tx, missing


def median(rows, key):
    return round(st.median([r[key] for r in rows]), 4) if rows else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-root", default="data/fig1b")
    ap.add_argument("--logs", default="data/logs")
    ap.add_argument("--out", default="data/fig1b")
    ap.add_argument("--out-tab1", default="data/tab1")
    args = ap.parse_args()

    logmap = {}
    for p in glob.glob(os.path.join(args.logs, "cc_timing_*.log")):
        logmap.update(load_cc_log(p))
    tx, missing = collect(args.raw_root, logmap)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cols = ["scheme", "profile", "config", "rep", "tx_id", "cc_core_ms", "crypto_ms",
            "other_cc_ms", "endorse_ms", "transport_ms", "commit_ms", "tx_total_ms"]
    with open(out / "fig1b_onchain_tx.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in tx:
            w.writerow(r)

    groups = {}
    for r in tx:
        groups.setdefault(r["profile"], []).append(r)
    with open(out / "fig1b_onchain_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["profile", "n_tx", "cc_core_ms", "crypto_ms", "other_cc_ms",
                    "endorse_ms", "transport_ms", "commit_ms", "tx_total_ms"])
        for prof, rows in sorted(groups.items()):
            w.writerow([prof, len(rows), median(rows, "cc_core_ms"), median(rows, "crypto_ms"),
                        median(rows, "other_cc_ms"), median(rows, "endorse_ms"),
                        median(rows, "transport_ms"), median(rows, "commit_ms"),
                        median(rows, "tx_total_ms")])

    print(f"merged tx={len(tx)} groups={len(groups)} missing_cc_log={missing}")

    tab = Path(args.out_tab1)
    tab.mkdir(parents=True, exist_ok=True)
    per_rep = {}
    for r in tx:
        per_rep.setdefault((r["config"], r["profile"], r["rep"]), []).append(r)
    with open(tab / "tab1_cumulative.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "profile", "n_tx_per_rep", "cumulative_s_mean",
                    "cumulative_s_median", "reps"])
        keys = sorted({(c, p) for (c, p, _) in per_rep})
        for cfg, prof in keys:
            totals = [sum(x["tx_total_ms"] for x in rows) / 1000.0
                      for (c, p, _), rows in per_rep.items() if c == cfg and p == prof]
            n_tx = len(per_rep[(cfg, prof, next(k[2] for k in per_rep
                                                 if k[0] == cfg and k[1] == prof))])
            w.writerow([cfg, prof, n_tx, round(sum(totals) / len(totals), 3),
                        round(st.median(totals), 3), len(totals)])
    print("wrote", tab / "tab1_cumulative.csv")


if __name__ == "__main__":
    main()
