{
  lib,
  src,
  buildGoModule,
}:
buildGoModule (finalAttrs: {
  pname = "hermes-agent-operator";
  version = "0.7.0"; # keep in sync with dist/chart/Chart.yaml `appVersion`

  inherit src;

  vendorHash = "sha256-+7HXfCW6znsfKSGdJa5Obb3ZmOkUyWwmy0XRP/cT1x0=";

  subPackages = [ "cmd" ];

  # Static, like the Dockerfile's build. The symbol is `main.version`: cmd/ is
  # a main package, so the linker knows it as `main`, not by its import path.
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${finalAttrs.version}"
  ];

  # The unit suites start a real control plane through envtest, which needs
  # kube-apiserver/etcd binaries downloaded by `setup-envtest` — no network in
  # the sandbox. `make test` remains the test gate.
  doCheck = false;

  postInstall = ''
    mv $out/bin/cmd $out/bin/hermes-agent-operator
  '';

  meta = {
    description = "Kubernetes operator that manages Hermes agents as custom resources";
    homepage = "https://github.com/hermeum/hermes-agent-operator";
    license = lib.licenses.mit;
    sourceProvenance = with lib.sourceTypes; [ fromSource ];
    maintainers = with lib.maintainers; [ aldoborrero ];
    mainProgram = "hermes-agent-operator";
    platforms = lib.platforms.unix;
  };
})
