# Contributing

## Prerequisites

- Go 1.24+
- Docker
- kubectl
- [Kind](https://kind.sigs.k8s.io/) (for e2e tests only)

Or, with [Nix](https://nixos.org/download/) (flakes enabled), skip installing
any of them:

```sh
nix develop        # or `direnv allow`, which loads the same shell
```

The shell brings Go, gopls, golangci-lint, kubectl, Kind, Helm, `make` and
`just`. The Makefile still downloads its own pinned controller-gen, kustomize
and setup-envtest into `./bin`, so generated manifests never drift with the
nixpkgs versions.

## Generate code and manifests

After changing API types (`api/v1alpha1/`), regenerate the DeepCopy methods and CRD manifests:

```sh
make generate   # regenerate zz_generated.deepcopy.go
make manifests  # regenerate CRDs and RBAC from markers
kubebuilder edit --plugins=helm/v2-alpha
```

## Lint

```sh
make lint       # check for issues
make lint-fix   # check and auto-fix
```

Run `make lint-fix` after any code change before committing.

## Test

```sh
make test       # unit tests (no cluster required)
make test-e2e   # e2e tests against a Kind cluster
```

## Build and run locally

```sh
# Run the operator against the current kubeconfig context (installs CRDs first)
make install
make run
```

## Nix

The flake ([numtide/blueprint](https://github.com/numtide/blueprint), outputs
under `nix/`) provides the dev shell, a formatter and a build of the manager
binary:

```sh
nix build .#hermes-agent-operator   # build the manager
nix fmt                             # format nix, go, yaml, json, toml, shell
nix flake check                     # what the Nix CI job runs
```

`nix flake check` builds the package, evaluates the dev shell and fails on
unformatted files. It does not replace `make test` — the unit suites need an
envtest control plane, which the build sandbox cannot download.

`just` wraps both worlds; run `just` for the list of recipes.

## Pull request titles

PR titles must follow the [Conventional Commits](https://www.conventionalcommits.org/) format and are validated automatically by CI:

```
<type>: <short description>
```

Permitted types:

| Type | When to use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no logic change |
| `refactor` | Code restructure, no feature/fix |
| `perf` | Performance improvement |
| `test` | Adding or fixing tests |
| `build` | Build system changes |
| `ci` | CI configuration changes |
| `chore` | Maintenance tasks |
| `revert` | Reverts a previous commit |

Scopes are optional: `feat(api): add webhook field` is valid but `feat: add webhook field` is equally fine.

