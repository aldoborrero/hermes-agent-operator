package usecase

import (
	"context"
	"slices"
	"testing"

	agentsv1alpha1 "hermeum/hermes-agent-operator/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

func findEnv(envs []corev1.EnvVar, name string) *corev1.EnvVar {
	for i := range envs {
		if envs[i].Name == name {
			return &envs[i]
		}
	}
	return nil
}

func TestEgressPodInputs(t *testing.T) {
	ha := egressHA(nil)
	inputs := func(t *testing.T, secrets map[string]*corev1.Secret) string {
		t.Helper()
		_, hash, err := NewHermesAgentUseCase(newFakeEgressKube(secrets), silentTelemetry{}).egressPodInputs(context.Background(), ha)
		if err != nil {
			t.Fatal(err)
		}
		return hash
	}
	base := func() map[string]*corev1.Secret {
		return map[string]*corev1.Secret{
			egressCredsSecret:          credsSecret("OPENROUTER_API_KEY"),
			ha.GetEgressSecretName():   {Data: map[string][]byte{"OPENROUTER_API_KEY": []byte("token")}},
			ha.GetEgressCASecretName(): {Data: map[string][]byte{"ca.crt": []byte("cert"), "ca.key": []byte("key")}},
		}
	}
	baseline := inputs(t, base())

	tests := []struct {
		name        string
		mutate      func(map[string]*corev1.Secret)
		expectRolls bool
	}{
		{
			name:        "rotating a real key",
			mutate:      func(s map[string]*corev1.Secret) { s[egressCredsSecret].Data["OPENROUTER_API_KEY"] = []byte("rotated") },
			expectRolls: true,
		},
		{
			name:        "rotating the ca certificate",
			mutate:      func(s map[string]*corev1.Secret) { s[ha.GetEgressCASecretName()].Data["ca.crt"] = []byte("new") },
			expectRolls: true,
		},
		{
			name: "changing the egress secret",
			mutate: func(s map[string]*corev1.Secret) {
				s[ha.GetEgressSecretName()].Data["OPENROUTER_API_KEY"] = []byte("new")
			},
			expectRolls: true,
		},
		{
			name:   "changing a credentials secret key that is no credential",
			mutate: func(s map[string]*corev1.Secret) { s[egressCredsSecret].Data["UNRELATED"] = []byte("x") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := base()
			tt.mutate(secrets)
			if rolls := inputs(t, secrets) != baseline; rolls != tt.expectRolls {
				t.Errorf("pod restart: got %v, expected %v", rolls, tt.expectRolls)
			}
		})
	}
}

// egressContainerFixture returns an egress-enabled agent and the credentials
// it resolves from a Secret holding OpenRouter and Google (Gemini alias) keys.
func egressContainerFixture(t *testing.T) (*agentsv1alpha1.HermesAgent, []agentsv1alpha1.EgressCredential) {
	t.Helper()
	ha := egressHA(nil)
	creds, err := ha.GetEgress().ResolveCredentials([]string{"OPENROUTER_API_KEY", "GOOGLE_API_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	return ha, creds
}

// TestBuildEgressContainerEnv checks the agent gets proxy tokens and proxy
// env while the sidecar gets the real keys.
func TestBuildEgressContainerEnv(t *testing.T) {
	ha, creds := egressContainerFixture(t)
	sts := buildEgressContainer(ha, buildStatefulSet(ha, "cfg"), creds, "h1")

	agent := findHermesContainer(sts)
	for _, name := range []string{"OPENROUTER_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"} {
		env := findEnv(agent.Env, name)
		if env == nil || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("expected %s on the agent from a secretKeyRef, got %+v", name, env)
		}
		if ref := env.ValueFrom.SecretKeyRef; ref.Name != ha.GetEgressSecretName() || ref.Key != name {
			t.Errorf("%s must come from its own egress secret key, got %s/%s", name, ref.Name, ref.Key)
		}
	}
	for _, env := range agent.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == egressCredsSecret {
			t.Errorf("the agent must never reference the credentials secret, got %s", env.Name)
		}
	}
	if got := findEnv(agent.Env, "HTTPS_PROXY"); got == nil || got.Value != "http://127.0.0.1:9090" {
		t.Errorf("unexpected HTTPS_PROXY %+v", got)
	}
	if got := findEnv(agent.Env, "HTTP_PROXY"); got == nil || got.Value != "http://127.0.0.1:9091" {
		t.Errorf("unexpected HTTP_PROXY %+v", got)
	}

	proxy := findContainer(sts, egressContainerName)
	if proxy == nil {
		t.Fatal("expected the iron-proxy sidecar")
	}
	gemini := findEnv(proxy.Env, "GEMINI_API_KEY")
	if gemini == nil || gemini.ValueFrom.SecretKeyRef.Name != egressCredsSecret || gemini.ValueFrom.SecretKeyRef.Key != "GOOGLE_API_KEY" {
		t.Errorf("expected the sidecar's GEMINI_API_KEY read from the alias key, got %+v", gemini)
	}
	if sts.Spec.Template.Annotations[domain+"/egress-hash"] != "h1" {
		t.Error("expected the egress hash on the pod template")
	}
}

func TestBuildEgressContainer(t *testing.T) {
	ha, creds := egressContainerFixture(t)

	t.Run("the agent mounts the ca certificate, never its key", func(t *testing.T) {
		sts := buildEgressContainer(ha, buildStatefulSet(ha, "cfg"), creds, "h1")
		for _, v := range sts.Spec.Template.Spec.Volumes {
			if v.Name != egressAgentCAVolume {
				continue
			}
			for _, item := range v.Secret.Items {
				if item.Key != agentsv1alpha1.EgressCAManagedCertKey {
					t.Errorf("agent ca volume exposes %q", item.Key)
				}
			}
			return
		}
		t.Error("expected the agent ca volume")
	})

	t.Run("a user-supplied ca is projected under the fixed names", func(t *testing.T) {
		withCA := ha.DeepCopy()
		withCA.Spec.Egress.CA = &agentsv1alpha1.EgressCA{SecretRef: &agentsv1alpha1.EgressSecretRef{Name: "cm-ca"}}
		sts := buildEgressContainer(withCA, buildStatefulSet(withCA, "cfg"), creds, "h1")
		for _, v := range sts.Spec.Template.Spec.Volumes {
			if v.Name != egressConfigVolume {
				continue
			}
			ca := v.Projected.Sources[1].Secret
			want := []corev1.KeyToPath{{Key: "tls.crt", Path: "ca.crt"}, {Key: "tls.key", Path: "ca.key"}}
			if ca.Name != "cm-ca" || !slices.Equal(ca.Items, want) {
				t.Errorf("unexpected ca projection %+v", ca)
			}
			return
		}
		t.Error("expected the egress config volume")
	})

	t.Run("disabled egress leaves the statefulset untouched", func(t *testing.T) {
		off := minimalHA()
		sts := buildEgressContainer(off, buildStatefulSet(off, "cfg"), nil, "")
		if findContainer(sts, egressContainerName) != nil || findEnv(findHermesContainer(sts).Env, "HTTPS_PROXY") != nil {
			t.Error("expected no egress wiring")
		}
	})
}
