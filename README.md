# Delivery protocol — experiment artefact

## Dependencies

| Component                | Version | Notes                                                        |
| ------------------------ | ------- | ------------------------------------------------------------ |
| Go                       | 1.25.7  | `run/_env.ps1` reads `THESIS_GOROOT`; set it when your toolchain lives elsewhere |
| gnark                    | v0.15.0 | Groth16 over BLS12-381                                       |
| gnark-crypto             | v0.20.1 | BLS12-381 and secp256k1 arithmetic                           |
| Python                   | 3.10+   | plotting only                                                |
| matplotlib               | 3.5+    | plotting only                                                |
| Hyperledger Fabric       | 2.5.7   | 2 organizations, 2 peers, 1 Raft orderer                     |
| Fabric Gateway Go client | v1.8.0  | on-chain driver                                              |
| Hyperledger Caliper      | 0.7.1   | throughput and latency benchmark                             |
| Node.js                  | >= 22   | Caliper runtime                                              |
| Docker + compose         | current | runs the Fabric network in WSL2                              |

`blockchain/fabric/network/version-lock.env` is the single source of truth for
the Fabric, Go, Caliper and Node versions.

### Environment variables

| Name                 | Default                | Meaning                                               |
| -------------------- | ---------------------- | ----------------------------------------------------- |
| `THESIS_GOROOT`      | `run/_env.ps1` default | Go installation root                                  |
| `THESIS_GOPATH`      | `run/_env.ps1` default | Go module cache and binaries                          |
| `FABRIC_SAMPLES_DIR` | empty                  | path to `fabric-samples` (required for on-chain runs) |
| `CHANNEL`            | `mychannel`            | Fabric channel                                        |
| `CHAINCODE`          | `c5bc`                 | chaincode name                                        |
| `REPS` / `WARMUPS`   | `10` / `1`             | on-chain repetitions                                  |

## Layout

```
blockchain/
  artifacts/c5_l1_507/       Groth16 setup for the canonical relation 
  bridge/                    public-only task reconstruction, VK-only verifier
  caliper/                   Hyperledger Caliper benchmark definitions
  experiments/
    analysis/                statistics and communication-volume accounting
    cmd/fig1a/               Fig. 1(a)  proof verification (in-process)
    cmd/onchain/             Fig. 1(b), Table 1, end-to-end ( Fabric)
    cmd/fig2/                Fig. 2     receiver-recovery time
    cmd/fig3/                Fig. 3     proof organisation
    cmd/fig4/                Fig. 4     recovery time vs output dimension
    cmd/fig5/                Fig. 5     delivery volume vs output dimension
    cmd/tab2/                Table 2    dynamic communication volumes
    cmd/tab3/                Table 3    prover setup, proving and memory
    cmd/selftest/            functional validation
    cmd/setupgen/            regenerates the setup artifacts
    cmd/verifyctl/           fixture generation
    offline/                 shared measurement code
  fabric/
    ccaas/                   chaincode-as-a-service image and deployment
    chaincode/               chaincode: model, verify core, contracts
    client/                  Fabric Gateway clients
    network/                 bring-up, health check and teardown scripts
  protocol_fidelity/         Gai et al. faithful adapter and the C5 relation
internal/c5/                 protocol core: circuit, host, m1 task model
plots/                       figure scripts (English and Chinese output)
run/                         one script per experiment plus launchers
data/                        experiment output (created at run time)
figures/                     generated figures (created at run time)
```

## Experiment map

| Artefact | Command | Fabric required |
| --- | --- | --- |
| Fig. 1(a) proof verification | `run/fig1a.ps1` | no |
| Fig. 1(b) chaincode verification | `run/fig1b.ps1` | yes |
| Fig. 2 receiver recovery | `run/fig2.ps1` | no |
| Fig. 3 proof organisation | `run/fig3.ps1` | no |
| Fig. 4 recovery vs `L` | `run/fig4.ps1` | no |
| Fig. 5 delivery volume vs `L` | `run/fig5.ps1` | no |
| Table 1 Fabric transaction times | `run/tab1.ps1` | yes |
| Table 2 communication volumes | `run/tab2.ps1` | no |
| Table 3 prover resources | `run/tab3.ps1` | no |
| Functional validation | `run/selftest.ps1` | no |

## Running

All commands are PowerShell scripts, driven from `run/`. They set `GOROOT`,
`GOPATH`, `GOMAXPROCS` and the output directories themselves.

```powershell
# one experiment
run\fig1a.ps1 -Reps 30
run\fig2.ps1 -Reps 5
run\fig3.ps1
run\fig4.ps1 -Reps 30
run\fig5.ps1
run\tab2.ps1
run\tab3.ps1 -Ls "1,2,4"
run\selftest.ps1 -Reps 5

# everything that does not need Fabric
run\offline_all.ps1

# everything, including the on-chain runs (launched inside WSL)
run\run_all.ps1
run\run_all.ps1 -SkipFabric      # off-chain only
run\run_all.ps1 -WslRoot "/mnt/e/.../实现_C5_FULL_V4.5_PAPER_RELEASE"
```

Each script writes JSON and CSV output under `data/<experiment>/`, and a log
under `data/logs/`.

### On-chain experiments 

The on-chain measurements run against a Fabric network, always inside WSL:
the containers stop when the distro idles out, so bring-up, the experiment and
log collection must happen in one invocation.

```powershell
# 1. cross-compile the driver for linux/amd64
run\build_onchain.ps1

# 2. run inside WSL, in a single call
wsl -e bash /mnt/e/.../run/fabric_onchain.sh fig1b
wsl -e bash /mnt/e/.../run/fabric_onchain.sh tab1
```

`fabric_onchain.sh` keeps a small `wslkeep` container running so the distro does
not idle out and stop the network, starts the Fabric containers, waits for the
peers, records the ledger height before and after, runs our scheme and Gai et
al.'s configurations, and copies the chaincode timing log into `data/logs/`.

`run/fabric_check.sh` prints the container status, the channel height and the
committed chaincode definition; use it to verify the network before a long run.

`run/fig1b.ps1` and `run/tab1.ps1` forward their parameters (`-Reps`, `-Warmups`,
`-Profiles` / `-GaiProfile`) to `fabric_onchain.sh` and run it inside WSL; add
`-DryRun` to print the exact WSL command without executing it.

Network lifecycle is managed by `blockchain/fabric/network/`:

```bash
bash blockchain/fabric/network/bootstrap.sh   # tooling and artifact hash check
bash blockchain/fabric/network/up.sh          # network, channel and CCAAS chaincode
bash blockchain/fabric/network/healthcheck.sh # profile assertions
bash blockchain/fabric/network/down.sh        # teardown
```

## Plotting

```powershell
plots\plot_all.ps1            # both languages
plots\plot_all.ps1 -Lang en   # English only
plots\plot_fig1.ps1 -Lang zh  # a single figure, Chinese labels
```

Figures are written to `figures/<lang>/` as PDF, SVG and PNG. `plot_all.ps1`
first merges the raw Fabric records through `plots/merge_onchain.py`; pass
`-SkipOnchain` to skip that step for off-line-only data.

## Measurement boundaries

* Fig. 1(a) times a single Groth16 verification for our scheme and `w=8`
  chunk-wise ZKPoC verifications for Gai et al., in-process with the Windows
  QPC timer.
* Fig. 1(b) times the peer-side chaincode verification routine, excluding
  endorsement, ordering and commit.
* Fig. 2, 4 and 5 exclude proof generation, task registration and chain
  transactions; recovery receives exactly `t=f+1` valid deliveries.
* Table 2 volumes are derived from the message format, not from packet captures.
* Table 3 reports relation-specific setup separately from proving. Setup is a
  one-off cost and is not part of any per-transaction figure.

## Setup artifacts

Regenerate them with `run/fixtures.ps1` and `blockchain/experiments/cmd/setupgen`.
The chaincode image is built from a minimal context that copies `vk.bin` only.
