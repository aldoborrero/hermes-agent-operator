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
      # controller-gen and kustomize own these; reformatting them makes every
      # `make manifests` / `make build-installer` run show up as a diff.
      "config/crd/bases/**"
      "config/rbac/role.yaml"
      "config/webhook/manifests.yaml"
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
