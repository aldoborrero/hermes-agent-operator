package usecase

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	agentsv1alpha1 "hermeum/hermes-agent-operator/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// certPEM generates a self-signed certificate PEM for tests. isCA controls the
// CA basic constraint and, when true, the certSign key usage.
func certPEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidateEgressCASecret(t *testing.T) {
	caCert := certPEM(t, true)
	leafCert := certPEM(t, false)
	key := []byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")

	cases := []struct {
		name    string
		data    map[string][]byte
		wantErr bool
	}{
		{"valid CA", map[string][]byte{"tls.crt": caCert, "tls.key": key}, false},
		{"missing cert", map[string][]byte{"tls.key": key}, true},
		{"missing key", map[string][]byte{"tls.crt": caCert}, true},
		{"cert not PEM", map[string][]byte{"tls.crt": []byte("not a pem"), "tls.key": key}, true},
		{"cert is not a CA", map[string][]byte{"tls.crt": leafCert, "tls.key": key}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEgressCASecret("my-ca", tc.data)
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestBuildEgressCASecret(t *testing.T) {
	ha := egressHA(nil)
	secret, err := buildEgressCASecret(ha)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Name != ha.GetEgressCASecretName() {
		t.Errorf("expected name %q, got %q", ha.GetEgressCASecretName(), secret.Name)
	}
	if !strings.Contains(string(secret.Data[agentsv1alpha1.EgressCAManagedCertKey]), "BEGIN CERTIFICATE") {
		t.Error("expected a PEM certificate under ca.crt")
	}
	if len(secret.Data[agentsv1alpha1.EgressCAManagedKeyKey]) == 0 {
		t.Error("expected a key under ca.key")
	}
}

const egressCredsSecret = "llm-keys"

// egressHA returns an agent with egress enabled, reading credentials from
// egressCredsSecret, with the given config.
func egressHA(cfg *agentsv1alpha1.EgressConfig) *agentsv1alpha1.HermesAgent {
	ha := minimalHA()
	ha.Spec.Egress = &agentsv1alpha1.Egress{
		Enabled:     true,
		Credentials: &agentsv1alpha1.EgressCredentials{SecretRef: corev1.LocalObjectReference{Name: egressCredsSecret}},
		Config:      cfg,
	}
	return ha
}

func credNames(creds []agentsv1alpha1.EgressCredential) []string {
	names := make([]string, 0, len(creds))
	for _, c := range creds {
		names = append(names, c.Name+"<-"+c.SourceKey)
	}
	return names
}

func TestResolveEgressCredentials(t *testing.T) {
	t.Run("bundled providers present in the Secret, in hermes-agent order", func(t *testing.T) {
		creds, err := egressHA(nil).GetEgress().ResolveCredentials([]string{"ANTHROPIC_API_KEY", "UNRELATED", "OPENROUTER_API_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"OPENROUTER_API_KEY<-OPENROUTER_API_KEY", "ANTHROPIC_API_KEY<-ANTHROPIC_API_KEY"}
		if got := credNames(creds); !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if got := creds[1].GetMatchHeaders(); !slices.Equal(got, []string{"x-api-key", "Authorization"}) {
			t.Errorf("anthropic match headers: got %v", got)
		}
	})

	t.Run("an alias satisfies a provider and is its source key", func(t *testing.T) {
		creds, err := egressHA(nil).GetEgress().ResolveCredentials([]string{"GOOGLE_API_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		if got := credNames(creds); !slices.Equal(got, []string{"GEMINI_API_KEY<-GOOGLE_API_KEY"}) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("extraSecrets replace a bundled provider in place and append the rest", func(t *testing.T) {
		ha := egressHA(&agentsv1alpha1.EgressConfig{ExtraSecrets: []agentsv1alpha1.EgressSecret{
			{Name: "API_TOKEN", Hosts: []string{"api.example.com"}},
			{Name: "OPENAI_API_KEY", Hosts: []string{"llm.internal.example.com"}},
		}})
		creds, err := ha.GetEgress().ResolveCredentials([]string{"API_TOKEN", "OPENAI_API_KEY", "OPENROUTER_API_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"OPENROUTER_API_KEY<-OPENROUTER_API_KEY", "OPENAI_API_KEY<-OPENAI_API_KEY", "API_TOKEN<-API_TOKEN"}
		if got := credNames(creds); !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if !slices.Equal(creds[1].Hosts, []string{"llm.internal.example.com"}) {
			t.Errorf("expected the override's hosts, got %v", creds[1].Hosts)
		}
	})

	t.Run("an extraSecrets entry missing from the Secret is an error", func(t *testing.T) {
		ha := egressHA(&agentsv1alpha1.EgressConfig{ExtraSecrets: []agentsv1alpha1.EgressSecret{
			{Name: "API_TOKEN", Hosts: []string{"api.example.com"}},
		}})
		if _, err := ha.GetEgress().ResolveCredentials([]string{"OPENROUTER_API_KEY"}); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("no credentials Secret means no credentials", func(t *testing.T) {
		creds, err := (&agentsv1alpha1.Egress{Enabled: true}).ResolveCredentials(nil)
		if err != nil || len(creds) != 0 {
			t.Errorf("got %v, %v", creds, err)
		}
	})
}

func renderEgressConfig(t *testing.T, ha *agentsv1alpha1.HermesAgent, keys []string, existing *corev1.Secret) (*corev1.Secret, ironProxyConfig) {
	t.Helper()
	creds, err := ha.GetEgress().ResolveCredentials(keys)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := buildEgressSecret(ha, creds, existing)
	if err != nil {
		t.Fatal(err)
	}
	var cfg ironProxyConfig
	if err := yaml.Unmarshal(secret.Data[agentsv1alpha1.EgressProxyConfigKey], &cfg); err != nil {
		t.Fatal(err)
	}
	return secret, cfg
}

func TestBuildEgressSecret(t *testing.T) {
	t.Run("proxy.yaml binds loopback and keeps every iron-proxy default port off", func(t *testing.T) {
		_, cfg := renderEgressConfig(t, egressHA(nil), nil, nil)
		if cfg.DNS.Enabled {
			t.Error("expected DNS interception off")
		}
		for name, got := range map[string]string{
			"tunnel_listen": cfg.Proxy.TunnelListen,
			"http_listen":   cfg.Proxy.HTTPListen,
			"https_listen":  cfg.Proxy.HTTPSListen,
			"metrics":       cfg.Metrics.Listen,
		} {
			if !strings.HasPrefix(got, "127.0.0.1:") {
				t.Errorf("%s must bind loopback, got %q", name, got)
			}
		}
		if cfg.Proxy.TunnelListen != "127.0.0.1:9090" || cfg.Proxy.HTTPListen != "127.0.0.1:9091" {
			t.Errorf("unexpected listeners %q / %q", cfg.Proxy.TunnelListen, cfg.Proxy.HTTPListen)
		}
		if !slices.Equal(cfg.Proxy.UpstreamDenyCIDRs, defaultEgressUpstreamDenyCIDRs) {
			t.Errorf("expected the default deny list, got %v", cfg.Proxy.UpstreamDenyCIDRs)
		}
		if cfg.TLS.CACert != "/etc/iron-proxy/ca.crt" || cfg.TLS.CAKey != "/etc/iron-proxy/ca.key" {
			t.Errorf("unexpected CA paths %q / %q", cfg.TLS.CACert, cfg.TLS.CAKey)
		}
		if len(cfg.Transforms) != 1 || cfg.Transforms[0].Name != "allowlist" {
			t.Errorf("expected only the allowlist transform without credentials, got %+v", cfg.Transforms)
		}
	})

	t.Run("config fields flow into proxy.yaml", func(t *testing.T) {
		port := int32(18080)
		ha := egressHA(&agentsv1alpha1.EgressConfig{
			TunnelPort:        &port,
			UpstreamDenyCIDRs: []string{"169.254.0.0/16"},
			ExtraAllowedHosts: []string{"api.github.com", "openrouter.ai"},
			ExtraSecrets:      []agentsv1alpha1.EgressSecret{{Name: "API_TOKEN", Hosts: []string{"api.example.com"}}},
		})
		secret, cfg := renderEgressConfig(t, ha, []string{"API_TOKEN", "ANTHROPIC_API_KEY"}, nil)

		if cfg.Proxy.TunnelListen != "127.0.0.1:18080" || cfg.Proxy.HTTPListen != "127.0.0.1:18081" {
			t.Errorf("unexpected listeners %q / %q", cfg.Proxy.TunnelListen, cfg.Proxy.HTTPListen)
		}
		if !slices.Equal(cfg.Proxy.UpstreamDenyCIDRs, []string{"169.254.0.0/16"}) {
			t.Errorf("unexpected deny list %v", cfg.Proxy.UpstreamDenyCIDRs)
		}

		raw := string(secret.Data[agentsv1alpha1.EgressProxyConfigKey])
		for _, host := range []string{"api.anthropic.com", "api.github.com", "api.example.com"} {
			if !strings.Contains(raw, "- "+host+"\n") {
				t.Errorf("expected %s in the allowlist:\n%s", host, raw)
			}
		}
		if strings.Count(raw, "- openrouter.ai\n") != 1 {
			t.Errorf("expected openrouter.ai allowlisted once:\n%s", raw)
		}

		for _, name := range []string{"ANTHROPIC_API_KEY", "API_TOKEN"} {
			token := string(secret.Data[name])
			if token == "" {
				t.Fatalf("expected a proxy token for %s", name)
			}
			if !strings.Contains(raw, "proxy_value: "+token) || !strings.Contains(raw, "var: "+name) {
				t.Errorf("expected a secrets rule swapping %s:\n%s", name, raw)
			}
		}
		if !strings.HasPrefix(string(secret.Data["ANTHROPIC_API_KEY"]), "anthropic-") {
			t.Errorf("expected a hermes-style token prefix, got %q", secret.Data["ANTHROPIC_API_KEY"])
		}
		if strings.Count(raw, "require: false") != 2 || strings.Count(raw, "match_query: true") != 2 {
			t.Errorf("expected every rule to leave require off, which breaks tunnels, and to search the query:\n%s", raw)
		}
	})

	t.Run("tokens survive re-renders; dropped credentials lose theirs", func(t *testing.T) {
		ha := egressHA(nil)
		first, _ := renderEgressConfig(t, ha, []string{"OPENAI_API_KEY", "GROQ_API_KEY"}, nil)
		second, _ := renderEgressConfig(t, ha, []string{"OPENAI_API_KEY", "XAI_API_KEY"}, first)

		if string(second.Data["OPENAI_API_KEY"]) != string(first.Data["OPENAI_API_KEY"]) {
			t.Error("expected the OPENAI_API_KEY token to be preserved")
		}
		if _, ok := second.Data["GROQ_API_KEY"]; ok {
			t.Error("expected the GROQ_API_KEY token to be dropped")
		}
		if len(second.Data["XAI_API_KEY"]) == 0 {
			t.Error("expected a token minted for XAI_API_KEY")
		}

		again, _ := renderEgressConfig(t, ha, []string{"OPENAI_API_KEY", "XAI_API_KEY"}, second)
		if string(again.Data[agentsv1alpha1.EgressProxyConfigKey]) != string(second.Data[agentsv1alpha1.EgressProxyConfigKey]) {
			t.Error("expected proxy.yaml to be stable across reconciles")
		}
	})
}

// fakeEgressKube serves Secrets from memory. Only the methods the egress
// reconcilers touch are implemented; the rest panic through the nil embedded
// interface.
type fakeEgressKube struct {
	Kubernetes

	secrets map[string]*corev1.Secret
	deleted []string
}

func (f *fakeEgressKube) GetSecret(_ context.Context, param GetSecretParam) (*corev1.Secret, error) {
	return f.secrets[param.NamespacedName.Name], nil
}
func (f *fakeEgressKube) CreateSecretOwnedByHermesAgent(_ context.Context, param CreateSecretOfHermesAgentParam) error {
	f.secrets[param.Secret.Name] = param.Secret
	return nil
}
func (f *fakeEgressKube) UpdateSecretOwnedByHermesAgent(_ context.Context, param UpdateSecretOfHermesAgentParam) error {
	f.secrets[param.Secret.Name] = param.Secret
	return nil
}
func (f *fakeEgressKube) DeleteSecret(_ context.Context, param DeleteSecretParam) error {
	f.deleted = append(f.deleted, param.NamespacedName.Name)
	delete(f.secrets, param.NamespacedName.Name)
	return nil
}
func (f *fakeEgressKube) UpdateHermesAgentStatus(context.Context, UpdateHermesAgentStatusParam) error {
	return nil
}

func TestReconcileEgressSecret(t *testing.T) {
	credsSecret := &corev1.Secret{Data: map[string][]byte{"OPENROUTER_API_KEY": []byte("sk-or-real")}}

	t.Run("creates the Secret from the credentials Secret keys", func(t *testing.T) {
		kube := &fakeEgressKube{secrets: map[string]*corev1.Secret{egressCredsSecret: credsSecret}}
		ha := egressHA(nil)
		if _, err := NewHermesAgentUseCase(kube, silentTelemetry{}).reconcileEgressSecret(context.Background(), ha); err != nil {
			t.Fatal(err)
		}
		got := kube.secrets[ha.GetEgressSecretName()]
		if got == nil || len(got.Data["OPENROUTER_API_KEY"]) == 0 {
			t.Fatalf("expected the egress Secret with an OPENROUTER_API_KEY token, got %+v", got)
		}
		if string(got.Data["OPENROUTER_API_KEY"]) == "sk-or-real" {
			t.Error("the egress Secret must hold a proxy token, never the real key")
		}
		if ha.Status.ManagedResources.EgressSecret != ha.GetEgressSecretName() {
			t.Errorf("expected status to record the egress Secret, got %q", ha.Status.ManagedResources.EgressSecret)
		}
	})

	t.Run("fails while the credentials Secret is missing", func(t *testing.T) {
		kube := &fakeEgressKube{secrets: map[string]*corev1.Secret{}}
		if _, err := NewHermesAgentUseCase(kube, silentTelemetry{}).reconcileEgressSecret(context.Background(), egressHA(nil)); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("deletes the Secret once egress is disabled", func(t *testing.T) {
		ha := egressHA(nil)
		kube := &fakeEgressKube{secrets: map[string]*corev1.Secret{ha.GetEgressSecretName(): {}}}
		ha.Spec.Egress.Enabled = false
		if _, err := NewHermesAgentUseCase(kube, silentTelemetry{}).reconcileEgressSecret(context.Background(), ha); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(kube.deleted, []string{ha.GetEgressSecretName()}) {
			t.Errorf("expected the egress Secret deleted, got %v", kube.deleted)
		}
	})
}

func findEnv(envs []corev1.EnvVar, name string) *corev1.EnvVar {
	for i := range envs {
		if envs[i].Name == name {
			return &envs[i]
		}
	}
	return nil
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
		if ref := env.ValueFrom.SecretKeyRef; ref.Name != ha.GetEgressSecretName() {
			t.Errorf("%s must come from the egress Secret, got %s/%s", name, ref.Name, ref.Key)
		}
	}
	if findEnv(agent.Env, "GOOGLE_API_KEY").ValueFrom.SecretKeyRef.Key != "GEMINI_API_KEY" {
		t.Error("expected the alias to carry the canonical credential's token")
	}
	for _, env := range agent.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == egressCredsSecret {
			t.Errorf("the agent must never reference the credentials Secret, got %s", env.Name)
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

	t.Run("the agent mounts the CA certificate, never its key", func(t *testing.T) {
		sts := buildEgressContainer(ha, buildStatefulSet(ha, "cfg"), creds, "h1")
		for _, v := range sts.Spec.Template.Spec.Volumes {
			if v.Name != egressAgentCAVolume {
				continue
			}
			for _, item := range v.Secret.Items {
				if item.Key != agentsv1alpha1.EgressCAManagedCertKey {
					t.Errorf("agent CA volume exposes %q", item.Key)
				}
			}
			return
		}
		t.Error("expected the agent CA volume")
	})

	t.Run("a user-supplied CA is projected under the fixed names", func(t *testing.T) {
		withCA := ha.DeepCopy()
		withCA.Spec.Egress.CA = &agentsv1alpha1.EgressCA{SecretRef: &corev1.LocalObjectReference{Name: "cm-ca"}}
		sts := buildEgressContainer(withCA, buildStatefulSet(withCA, "cfg"), creds, "h1")
		for _, v := range sts.Spec.Template.Spec.Volumes {
			if v.Name != egressConfigVolume {
				continue
			}
			ca := v.Projected.Sources[1].Secret
			want := []corev1.KeyToPath{{Key: "tls.crt", Path: "ca.crt"}, {Key: "tls.key", Path: "ca.key"}}
			if ca.Name != "cm-ca" || !slices.Equal(ca.Items, want) {
				t.Errorf("unexpected CA projection %+v", ca)
			}
			return
		}
		t.Error("expected the egress config volume")
	})

	t.Run("disabled egress leaves the StatefulSet untouched", func(t *testing.T) {
		off := minimalHA()
		sts := buildEgressContainer(off, buildStatefulSet(off, "cfg"), nil, "")
		if findContainer(sts, egressContainerName) != nil || findEnv(findHermesContainer(sts).Env, "HTTPS_PROXY") != nil {
			t.Error("expected no egress wiring")
		}
	})
}

func TestGetEgressSourceSecretNames(t *testing.T) {
	ha := egressHA(nil)
	ha.Spec.Egress.CA = &agentsv1alpha1.EgressCA{SecretRef: &corev1.LocalObjectReference{Name: "cm-ca"}}
	if got := ha.GetEgressSourceSecretNames(); !slices.Equal(got, []string{egressCredsSecret, "cm-ca"}) {
		t.Errorf("got %v", got)
	}
	ha.Spec.Egress.Enabled = false
	if got := ha.GetEgressSourceSecretNames(); got != nil {
		t.Errorf("expected nothing watched while disabled, got %v", got)
	}
}
