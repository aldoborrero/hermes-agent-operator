# hermes-agent-operator
#
# Thin facade over the Makefile (kubebuilder owns it) and the flake.

default:
    @just --list

# Regenerate CRDs, RBAC and DeepCopy methods
generate:
    make manifests generate

# Run the unit tests (envtest control plane)
test:
    make test

# Run the e2e suite against a throwaway Kind cluster
test-e2e:
    make test-e2e

# Run golangci-lint
lint:
    make lint

# Run golangci-lint with autofixes
lint-fix:
    make lint-fix

# Run the manager against the cluster in ~/.kube/config
run:
    make run

# Format everything (nix, go, yaml, json, toml, shell, just)
fmt:
    nix fmt

# Every check CI runs: builds the operator and verifies formatting
check:
    nix flake check --log-format bar-with-logs

# Build the operator binary with Nix
build:
    nix build .#hermes-agent-operator --log-format bar-with-logs

# Build the container image with the Dockerfile (published from CI)
image:
    make docker-build
