# Entry points for the deployment and benchmark layers (GNU make).
#
#   make -C blockchain help
#   make -C blockchain go-build
#
# Targets that need Docker run inside WSL. Versions come from
# fabric/network/version-lock.env and are not repeated here.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

BLOCKCHAIN_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
REPO_ROOT := $(abspath $(BLOCKCHAIN_DIR)/..)
NETWORK_DIR := $(BLOCKCHAIN_DIR)/fabric/network
CCAAS_DIR := $(BLOCKCHAIN_DIR)/fabric/ccaas
CALIPER_DIR := $(BLOCKCHAIN_DIR)/caliper

.PHONY: help go-build go-test cc-image net-up net-down net-health caliper-install \
        caliper-run-c5 caliper-run-schemea

# Docker is required by every target whose name starts with cc-, net- or caliper-run.
help:
	@echo "blockchain targets:"
	@echo "  help                 list targets"
	@echo "  go-build             go build ./..."
	@echo "  go-test              go test  ./..."
	@echo "  cc-image             build the CCAAS chaincode image (Docker)"
	@echo "  net-up               start test-network and deploy the chaincode (Docker)"
	@echo "  net-down             stop the network and remove the chaincode container (Docker)"
	@echo "  net-health           assert no secret material is on chain (Docker)"
	@echo "  caliper-install      npm ci and bind Caliper to Fabric 2.5 (Node >= 22)"
	@echo "  caliper-run-c5       Caliper workload for our scheme (Docker)"
	@echo "  caliper-run-schemea  Caliper workload for Gai et al. (Docker)"

go-build:
	cd "$(BLOCKCHAIN_DIR)" && go build ./...

go-test:
	cd "$(BLOCKCHAIN_DIR)" && go test ./...

cc-image:
	bash "$(BLOCKCHAIN_DIR)/scripts/prepare_buildctx.sh"
	docker build -f "$(CCAAS_DIR)/Dockerfile" -t c5bc-ccaas:2.5.7 "$(BLOCKCHAIN_DIR)/third_party/buildctx"

net-up:
	bash "$(NETWORK_DIR)/up.sh"

net-down:
	bash "$(NETWORK_DIR)/down.sh"

net-health:
	bash "$(NETWORK_DIR)/healthcheck.sh"

caliper-install:
	cd "$(CALIPER_DIR)" && if [ -f package-lock.json ]; then npm ci; else npm install --package-lock-only --ignore-scripts && npm ci; fi
	cd "$(CALIPER_DIR)" && npx caliper bind --caliper-bind-sut fabric:2.5

caliper-run-c5:
	cd "$(CALIPER_DIR)" && npx caliper launch manager \
	  --caliper-workspace . \
	  --caliper-benchconfig benchmarks/benchmark-verifyC5.yaml \
	  --caliper-networkconfig networks/network-local.yaml \
	  --caliper-report-path reports --caliper-report-format html --caliper-report-charting true

caliper-run-schemea:
	cd "$(CALIPER_DIR)" && npx caliper launch manager \
	  --caliper-workspace . \
	  --caliper-benchconfig benchmarks/benchmark-verifySchemeA.yaml \
	  --caliper-networkconfig networks/network-local.yaml \
	  --caliper-report-path reports --caliper-report-format html --caliper-report-charting true
