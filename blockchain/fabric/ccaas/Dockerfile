# Multi-stage build for the chaincode-as-a-service (CCAAS) image.
#
# The build context must include both module files and the necessary subtrees.
# fabric/network/up.sh normally calls scripts/prepare_buildctx.sh to generate
# a minimal context rather than copying the entire repository.
#
# The image contains the chaincode binary, vk.bin and manifest.json only. No COPY
# line references pk.bin or ccs.bin, which keeps the proving key off chain.

# ---- stage 1: build ----
FROM golang:1.25-bookworm AS builder

ENV CGO_ENABLED=0
ENV GOFLAGS=-trimpath
ENV GOPROXY=https://goproxy.cn,direct

WORKDIR /src

# Copy the module files first so dependency download stays cached.
COPY go.mod go.sum ./
COPY blockchain/go.mod blockchain/go.sum ./blockchain/
RUN cd blockchain && go mod download

# Copy only the subtrees the chaincode needs:
#   internal/**                    c5full/internal/c5/{m1,host,params} and dependencies
#   blockchain/bridge/**           public-only task reconstruction and VK-only verifier
#   blockchain/fabric/chaincode/** model / verify / contracts / cmd/cc
#   blockchain/protocol_fidelity/** protocol-fidelity checks used by the verify package
COPY internal/ ./internal/
COPY blockchain/bridge/ ./blockchain/bridge/
COPY blockchain/fabric/chaincode/ ./blockchain/fabric/chaincode/
COPY blockchain/protocol_fidelity/ ./blockchain/protocol_fidelity/
# Only vk.bin and manifest.json are copied: pk.bin (571MB) and ccs.bin (53.9MB)
# never enter the build context.
COPY blockchain/artifacts/c5_l1_507/vk.bin        ./blockchain/artifacts/c5_l1_507/vk.bin
COPY blockchain/artifacts/c5_l1_507/manifest.json ./blockchain/artifacts/c5_l1_507/manifest.json

RUN cd blockchain && go build -trimpath -o /out/cc ./fabric/chaincode/cmd/cc

# ---- stage 2: runtime ----
# debian:bookworm-slim keeps a shell, which the "no proving key in the image"
# evidence command relies on:
#   docker run --rm <image> ls -l /opt/chaincode/artifacts/c5_l1_507
FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin chaincode

WORKDIR /opt/chaincode

COPY --from=builder /out/cc /opt/chaincode/cc
# The chaincode verifies the sha256 of vk.bin against the canonical profile on startup.
COPY blockchain/artifacts/c5_l1_507/vk.bin        /opt/chaincode/artifacts/c5_l1_507/vk.bin
COPY blockchain/artifacts/c5_l1_507/manifest.json /opt/chaincode/artifacts/c5_l1_507/manifest.json

ENV C5_VK_DIR=/opt/chaincode/artifacts/c5_l1_507
# Default listen address; deploy.sh injects the real CHAINCODE_ID and address,
# because the package id is only known after the package is assembled.
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999

EXPOSE 9999

USER chaincode

ENTRYPOINT ["/opt/chaincode/cc"]
