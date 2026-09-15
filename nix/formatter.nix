{
  flake,
  inputs,
  pkgs,
  ...
}:
let
  mod = inputs.treefmt-nix.lib.evalModule pkgs {
    projectRootFile = "flake.nix";

    programs = {
      # nix: deadnix strips dead code, then nixfmt formats.
      deadnix.enable = true;
      deadnix.no-lambda-pattern-names = true; # keep callPackage-style argument sets
      deadnix.priority = 1;
      nixfmt.enable = true;
      nixfmt.priority = 2;

      # go
      gofmt.enable = true;

      # shell: shellcheck lints, then shfmt formats.
      shellcheck.enable = true;
      shellcheck.includes = [
        "*.sh"
        "*.bash"
        "*.envrc"
        "*.envrc.*"
      ];
      shellcheck.priority = 1;
      shfmt.enable = true;
      shfmt.includes = [
        "*.sh"
        "*.bash"
        "*.envrc"
        "*.envrc.*"
      ];
      shfmt.priority = 2;

      # yaml
      yamlfmt.enable = true;
      yamlfmt.settings.formatter = {
        type = "basic";
        indent = 2;
        retain_line_breaks = true;
      };

      # json
      jsonfmt.enable = true;

      # toml
      taplo.enable = true;

      # justfile
      just.enable = true;
    };

    settings.excludes = [
      # Trees a generator owns. kubebuilder scaffolds and refreshes config/,
      # controller-gen writes the CRDs and RBAC inside it, and dist/ comes out
      # of kustomize and the Helm plugin — reformatting any of them turns the
      # next `make manifests` / `kubebuilder edit` into a conflict.
      "config/**"
      "dist/**"
      "skills/hermes-agent-operator/crd.yaml"
    ];
  };

  wrapper = mod.config.build.wrapper;
in
wrapper
// {
  passthru = wrapper.passthru // {
    tests.check = mod.config.build.check flake;
  };
}
