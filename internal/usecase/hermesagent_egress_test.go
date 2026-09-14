package usecase

import (
	"strings"
	"testing"

	agentsv1alpha1 "hermeum/hermes-agent-operator/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

func enabledEgressHA() *agentsv1alpha1.HermesAgent {
	ha := minimalHA()
	enabled := true
	ha.Spec.Egress = &agentsv1alpha1.Egress{
		Enabled:      &enabled,
		AllowedHosts: []string{"openrouter.ai"},
		Inject: []agentsv1alpha1.EgressInject{
			{
				Host: "api.example.com",
				ValueFrom: corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "mealie-secrets"},
						Key:                  "MEALIE_API_TOKEN",
					},
				},
			},
		},
	}
	return ha
}

func TestBuildEgressProxyYAML(t *testing.T) {
	t.Run("allowlist union and secrets/inject entry", func(t *testing.T) {
		ha := enabledEgressHA()

		out, err := buildEgressProxyYAML(ha)
		if err != nil {
			t.Fatal(err)
		}

		// DNS interception is off — we use the explicit HTTPS_PROXY tunnel.
		if !strings.Contains(out, "enabled: false") {
			t.Errorf("expected dns.enabled false, got:\n%s", out)
		}
		if !strings.Contains(out, "tunnel_listen: :8080") {
			t.Errorf("expected tunnel_listen :8080, got:\n%s", out)
		}
		// Allowlist must include both the explicit host and the injected host.
		if !strings.Contains(out, "openrouter.ai") {
			t.Errorf("expected allowlist domain openrouter.ai, got:\n%s", out)
		}
		if !strings.Contains(out, "api.example.com") {
			t.Errorf("expected injected host api.example.com in allowlist, got:\n%s", out)
		}
		// A secrets/inject entry for the rule, keyed by the derived env var.
		if !strings.Contains(out, "name: secrets") {
			t.Errorf("expected a secrets transform, got:\n%s", out)
		}
		if !strings.Contains(out, "var: EGRESS_CRED_0") {
			t.Errorf("expected source.var EGRESS_CRED_0, got:\n%s", out)
		}
		if !strings.Contains(out, "header: Authorization") {
			t.Errorf("expected default Authorization header, got:\n%s", out)
		}
		if !strings.Contains(out, "Bearer {{ .Value }}") {
			t.Errorf("expected default Bearer formatter, got:\n%s", out)
		}
		// MITM CA paths point at the mounted secret.
		if !strings.Contains(out, "ca_cert: /etc/iron-proxy/ca.crt") {
			t.Errorf("expected ca_cert path, got:\n%s", out)
		}
	})

	t.Run("deterministic across renders", func(t *testing.T) {
		ha := enabledEgressHA()
		a, err := buildEgressProxyYAML(ha)
		if err != nil {
			t.Fatal(err)
		}
		b, err := buildEgressProxyYAML(ha)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("proxy.yaml render must be deterministic:\n%s\n---\n%s", a, b)
		}
	})

	t.Run("no secrets transform when no inject rules", func(t *testing.T) {
		ha := minimalHA()
		enabled := true
		ha.Spec.Egress = &agentsv1alpha1.Egress{Enabled: &enabled, AllowedHosts: []string{"openrouter.ai"}}
		out, err := buildEgressProxyYAML(ha)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "name: secrets") {
			t.Errorf("did not expect a secrets transform, got:\n%s", out)
		}
	})
}

func TestBuildEgressCASecret(t *testing.T) {
	ha := enabledEgressHA()
	secret, err := buildEgressCASecret(ha)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Name != ha.GetEgressCASecretName() {
		t.Errorf("expected name %q, got %q", ha.GetEgressCASecretName(), secret.Name)
	}
	if len(secret.Data[egressCACertKey]) == 0 {
		t.Error("expected a ca.crt in the CA secret")
	}
	if len(secret.Data[egressCAKeyKey]) == 0 {
		t.Error("expected a ca.key in the CA secret")
	}
	if !strings.Contains(string(secret.Data[egressCACertKey]), "BEGIN CERTIFICATE") {
		t.Error("expected PEM-encoded certificate")
	}
}

func TestBuildEgressContainer(t *testing.T) {
	t.Run("enabled: iron-proxy sidecar and agent proxy env", func(t *testing.T) {
		ha := enabledEgressHA()
		sts := buildStatefulSet(ha)

		proxy := findContainer(sts, "iron-proxy")
		if proxy == nil {
			t.Fatal("expected iron-proxy sidecar container")
		}
		if !hasEnvVar(proxy.Env, "EGRESS_CRED_0") {
			t.Error("expected EGRESS_CRED_0 env var on the sidecar sourced from the user secret")
		}

		c := findHermesContainer(sts)
		if c == nil {
			t.Fatal("expected hermes-agent container")
		}
		for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"} {
			if !hasEnvVar(c.Env, name) {
				t.Errorf("expected %s on the hermes-agent container", name)
			}
		}
		if !hasVolumeMount(c.VolumeMounts, "egress-agent-ca") {
			t.Error("expected the CA cert mounted into the agent container")
		}
	})

	t.Run("disabled: no sidecar and no proxy env", func(t *testing.T) {
		ha := minimalHA()
		sts := buildStatefulSet(ha)

		if findContainer(sts, "iron-proxy") != nil {
			t.Error("did not expect an iron-proxy sidecar when egress is disabled")
		}
		c := findHermesContainer(sts)
		if c == nil {
			t.Fatal("expected hermes-agent container")
		}
		if hasEnvVar(c.Env, "HTTPS_PROXY") {
			t.Error("did not expect HTTPS_PROXY when egress is disabled")
		}
	})
}
