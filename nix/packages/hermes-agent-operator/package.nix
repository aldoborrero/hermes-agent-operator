{
  lib,
  src,
  buildGoModule,
}:
buildGoModule (finalAttrs: {
  pname = "hermes-agent-operator";
  version = "0.7.0"; # keep in sync with dist/chart/Chart.yaml `appVersion`

  inherit src;

  vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

  subPackages = [ "cmd" ];

  # Matches the Dockerfile: a static binary reporting the same version string
  # that the anonymous heartbeat sends.
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X hermeum/hermes-agent-operator/cmd.version=${finalAttrs.version}"
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
