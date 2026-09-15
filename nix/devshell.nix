{ pkgs, perSystem }:
perSystem.devshell.mkShell {
  packages = (
    with pkgs;
    [
      just
      perSystem.self.formatter

      # Go toolchain. The version must satisfy the `go` directive in go.mod,
      # otherwise Go downloads a toolchain of its own on every build.
      go
      gopls
      gotools

      # Editor/ad-hoc linting. `make lint` still builds its own pinned
      # golangci-lint (plus the logcheck plugin from .custom-gcl.yml) into
      # ./bin, so CI and this shell can disagree — trust `make lint`.
      golangci-lint

      # Talking to a cluster: the e2e suite drives Kind, the chart is Helm.
      kubectl
      kind
      kubernetes-helm

      # The Makefile is still the source of truth for codegen and tests; it
      # downloads its own pinned controller-gen/kustomize/setup-envtest into
      # ./bin so generated files do not drift with the nixpkgs versions.
      gnumake
      jq
    ]
  );

  env = [
    {
      name = "NIX_PATH";
      value = "nixpkgs=${toString pkgs.path}";
    }
    {
      name = "NIX_DIR";
      eval = "$PRJ_ROOT/nix";
    }
    {
      # Keep the Go module cache in the project rather than $HOME.
      name = "GOPATH";
      eval = "$PRJ_ROOT/.go";
    }
  ];
}
