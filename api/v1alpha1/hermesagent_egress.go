/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// defaultEgressImage is the pinned iron-proxy image. iron-proxy publishes to
// Docker Hub only, without a leading "v" in its tags.
const defaultEgressImage = "docker.io/ironsh/iron-proxy:0.49.0"

// DefaultEgressTunnelPort mirrors hermes-agent's proxy.tunnel_port default.
const DefaultEgressTunnelPort = int32(9090)

// Egress CA Secret data keys: the operator-managed CA uses ca.crt/ca.key; a
// user-supplied CA (EgressCA.SecretRef, e.g. cert-manager) uses the standard
// kubernetes.io/tls keys.
const (
	EgressCAManagedCertKey = "ca.crt"
	EgressCAManagedKeyKey  = "ca.key"
	EgressCATLSCertKey     = "tls.crt"
	EgressCATLSKeyKey      = "tls.key"
)

// EgressProxyConfigKey is the key of the rendered iron-proxy proxy.yaml in the
// operator-managed egress Secret. Every other key of that Secret is the env
// var name of a credential, holding its opaque proxy token.
const EgressProxyConfigKey = "proxy.yaml"

// EgressConfigDir is where the iron-proxy sidecar mounts proxy.yaml and the CA,
// as ca.crt/ca.key whatever the source Secret's keys are.
const EgressConfigDir = "/etc/iron-proxy"

// defaultEgressAllowedHosts mirrors hermes-agent's _DEFAULT_ALLOWED_HOSTS
// (agent/proxy_sources/iron_proxy.py): the inference endpoints always allowed.
var defaultEgressAllowedHosts = []string{
	"openrouter.ai", "*.openrouter.ai", "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
	"api.x.ai", "api.mistral.ai", "api.groq.com", "api.together.xyz", "api.deepseek.com", "inference.nousresearch.com",
}

// egressProviders mirrors hermes-agent's _BEARER_PROVIDERS followed by
// _HEADER_AUTH_PROVIDERS, in the same order: the credentials hermes-agent
// knows how to swap, keyed by the env var the agent reads them from.
var egressProviders = []EgressSecret{
	{Name: "OPENROUTER_API_KEY", Hosts: []string{"openrouter.ai", "*.openrouter.ai"}},
	{Name: "OPENAI_API_KEY", Hosts: []string{"api.openai.com"}},
	{Name: "GROQ_API_KEY", Hosts: []string{"api.groq.com"}},
	{Name: "TOGETHER_API_KEY", Hosts: []string{"api.together.xyz"}},
	{Name: "DEEPSEEK_API_KEY", Hosts: []string{"api.deepseek.com"}},
	{Name: "MISTRAL_API_KEY", Hosts: []string{"api.mistral.ai"}},
	{Name: "XAI_API_KEY", Hosts: []string{"api.x.ai"}},
	{Name: "NOUS_API_KEY", Hosts: []string{"inference.nousresearch.com"}},
	{Name: "ANTHROPIC_API_KEY", Hosts: []string{"api.anthropic.com"}, MatchHeaders: []string{"x-api-key", "Authorization"}},
	{
		Name:         "AZURE_OPENAI_API_KEY",
		Hosts:        []string{"*.openai.azure.com", "*.cognitiveservices.azure.com", "*.services.ai.azure.com"},
		MatchHeaders: []string{"api-key", "Authorization"},
	},
	{
		Name:         "GEMINI_API_KEY",
		Hosts:        []string{"generativelanguage.googleapis.com"},
		MatchHeaders: []string{"x-goog-api-key"},
		Aliases:      []string{"GOOGLE_API_KEY"},
	},
}

// Egress configures an iron-proxy egress sidecar, mirroring hermes-agent's
// `proxy` config (`hermes egress`). The agent holds opaque proxy tokens instead
// of its provider API keys; iron-proxy, which alone holds the real keys,
// swaps each token for its key on the way out and denies every host not on
// its allowlist.
type Egress struct {
	// Enabled runs the iron-proxy sidecar and routes the agent's outbound
	// HTTP(S) through it.
	// +kubebuilder:default=false
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// Image is the full iron-proxy image reference, by tag or digest.
	// Defaults to a pinned iron-proxy release.
	// +optional
	Image string `json:"image,omitempty"`
	// Resources specifies compute resources for the iron-proxy container.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Credentials names the Secret holding the real provider API keys, keyed by
	// env var name (e.g. ANTHROPIC_API_KEY). Only the iron-proxy sidecar reads
	// it. Every key naming a provider hermes-agent knows, and every
	// config.extraSecrets entry, becomes a proxied credential: the agent gets a
	// proxy token under that env var name instead of the key, also where
	// spec.hermes env, envFrom or workspace.dotEnv carry the same name. Keys
	// not listed here reach the agent unchanged.
	// +optional
	Credentials *EgressCredentials `json:"credentials,omitempty"`
	// CA selects the iron-proxy MITM CA. When omitted, the operator generates
	// and preserves a self-signed CA.
	// +optional
	CA *EgressCA `json:"ca,omitempty"`
	// Config mirrors hermes-agent's `proxy` config section.
	// +optional
	Config *EgressConfig `json:"config,omitempty"`
}

// EgressCredentials names the Secret holding the real provider API keys.
type EgressCredentials struct {
	// SecretRef names a Secret in the HermesAgent's namespace. It must exist
	// before the agent is reconciled.
	// +kubebuilder:validation:Required
	SecretRef EgressSecretRef `json:"secretRef"`
}

// EgressSecretRef names a Secret in the HermesAgent's namespace.
type EgressSecretRef struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// EgressCA selects the source of the iron-proxy MITM CA.
type EgressCA struct {
	// SecretRef names a kubernetes.io/tls Secret in the agent's namespace
	// (keys tls.crt/tls.key) holding a CA certificate and key, the shape a
	// cert-manager Certificate with isCA: true produces. The operator reads it
	// but never creates, owns or deletes it, and rolls the pod when it changes.
	// +optional
	SecretRef *EgressSecretRef `json:"secretRef,omitempty"`
}

// EgressConfig mirrors hermes-agent's `proxy` config section.
type EgressConfig struct {
	// TunnelPort is the port of iron-proxy's CONNECT tunnel listener, which the
	// agent's HTTPS_PROXY points at. Its plain-HTTP listener, which HTTP_PROXY
	// points at, uses TunnelPort+1. Both bind loopback only. Defaults to 9090.
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=65534
	// +optional
	TunnelPort *int32 `json:"tunnelPort,omitempty"`
	// UpstreamDenyCIDRs are the ranges iron-proxy refuses to dial, checked
	// against the resolved address whatever the allowlist says. Defaults to
	// hermes-agent's list: loopback, link-local (cloud metadata), RFC1918, ULA,
	// IPv4-mapped IPv6, CGNAT and benchmark ranges.
	// +listType=set
	// +optional
	UpstreamDenyCIDRs []string `json:"upstreamDenyCidrs,omitempty"`
	// ExtraAllowedHosts are allowed on top of the bundled provider hosts.
	// Wildcards (*.example.com) are supported.
	// +listType=set
	// +optional
	ExtraAllowedHosts []string `json:"extraAllowedHosts,omitempty"`
	// ExtraSecrets are swapped on top of the bundled providers. An entry named
	// like a bundled provider replaces it.
	// +listType=map
	// +listMapKey=name
	// +optional
	ExtraSecrets []EgressSecret `json:"extraSecrets,omitempty"`
}

// EgressSecret maps a credential to the upstream hosts it is swapped on.
type EgressSecret struct {
	// Name is the env var the agent reads the credential from, and the key
	// holding the real value in the credentials Secret.
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Hosts are the upstream hosts the token is swapped on. They are allowed
	// implicitly.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:Required
	Hosts []string `json:"hosts"`
	// MatchHeaders are the request headers searched for the token, by name
	// (case-insensitive), or by regex when written as /pattern/. The query
	// string is always searched too. Defaults to Authorization.
	// +listType=set
	// +optional
	MatchHeaders []string `json:"matchHeaders,omitempty"`
	// Aliases are extra env var names the agent gets the same token under.
	// The real value may be stored under any of them in the credentials Secret.
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z_][A-Za-z0-9_]*$`
	// +optional
	Aliases []string `json:"aliases,omitempty"`
}

// EgressCredential is a credential iron-proxy swaps: the EgressSecret it
// derives from, plus the credentials Secret key holding its real value.
// +kubebuilder:object:generate=false
type EgressCredential struct {
	EgressSecret
	// SourceKey is the credentials Secret key holding the real value: Name, or
	// the first alias present when Name is not.
	SourceKey string
}

// IsEnabled reports whether the iron-proxy sidecar should run.
func (e *Egress) IsEnabled() bool {
	return e != nil && e.Enabled
}

// GetImage returns the iron-proxy image reference.
func (e *Egress) GetImage() string {
	if e == nil || strings.TrimSpace(e.Image) == "" {
		return defaultEgressImage
	}
	return strings.TrimSpace(e.Image)
}

// GetResources returns the iron-proxy container resource requirements.
func (e *Egress) GetResources() corev1.ResourceRequirements {
	if e == nil || e.Resources == nil {
		return corev1.ResourceRequirements{}
	}
	return *e.Resources
}

// GetCredentialsSecretName returns the name of the credentials Secret, or ""
// when none is set.
func (e *Egress) GetCredentialsSecretName() string {
	if e == nil || e.Credentials == nil {
		return ""
	}
	return e.Credentials.SecretRef.Name
}

// GetCASecretRefName returns the name of a user-supplied CA Secret, or "" when
// the operator manages its own CA.
func (e *Egress) GetCASecretRefName() string {
	if e == nil || e.CA == nil || e.CA.SecretRef == nil {
		return ""
	}
	return e.CA.SecretRef.Name
}

// GetTunnelPort returns the iron-proxy CONNECT tunnel port.
func (e *Egress) GetTunnelPort() int32 {
	if e == nil || e.Config == nil || e.Config.TunnelPort == nil {
		return DefaultEgressTunnelPort
	}
	return *e.Config.TunnelPort
}

// GetHTTPSProxyURL returns the agent's HTTPS_PROXY: the CONNECT tunnel.
func (e *Egress) GetHTTPSProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", e.GetTunnelPort())
}

// GetHTTPProxyURL returns the agent's HTTP_PROXY: the plain-HTTP listener on
// TunnelPort+1.
func (e *Egress) GetHTTPProxyURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", e.GetTunnelPort()+1)
}

// GetUpstreamDenyCIDRs returns the configured deny list, or nil to use
// hermes-agent's default.
func (e *Egress) GetUpstreamDenyCIDRs() []string {
	if e == nil || e.Config == nil {
		return nil
	}
	return e.Config.UpstreamDenyCIDRs
}

// GetAllowedHosts returns the bundled provider hosts followed by
// ExtraAllowedHosts, without duplicates. Credential hosts are added by the
// caller once the credentials are resolved.
func (e *Egress) GetAllowedHosts() []string {
	hosts := slices.Clone(defaultEgressAllowedHosts)
	if e == nil || e.Config == nil {
		return hosts
	}
	for _, h := range e.Config.ExtraAllowedHosts {
		if h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// ResolveCredentials returns the credentials iron-proxy swaps, given the keys
// present in the credentials Secret. Like hermes-agent's
// discover_provider_mappings, a bundled provider is included when its env var
// or one of its aliases is present; every ExtraSecrets entry is included and
// must be present. Bundled providers come first in hermes-agent's order, then
// ExtraSecrets in spec order; an ExtraSecrets entry named like a bundled
// provider replaces it in place.
func (e *Egress) ResolveCredentials(keys []string) ([]EgressCredential, error) {
	var extra []EgressSecret
	if e != nil && e.Config != nil {
		extra = e.Config.ExtraSecrets
	}
	sourceKey := func(s EgressSecret) string {
		for _, k := range s.EnvNames() {
			if slices.Contains(keys, k) {
				return k
			}
		}
		return ""
	}

	specs := slices.Clone(egressProviders)
	for _, s := range extra {
		if i := slices.IndexFunc(specs, func(p EgressSecret) bool { return p.Name == s.Name }); i >= 0 {
			specs[i] = s
		} else {
			specs = append(specs, s)
		}
	}

	var creds []EgressCredential
	envNames := map[string]string{}
	for _, s := range specs {
		k := sourceKey(s)
		if k == "" {
			if slices.ContainsFunc(extra, func(x EgressSecret) bool { return x.Name == s.Name }) {
				return nil, fmt.Errorf("extraSecrets %q: neither it nor an alias is a key of the credentials Secret", s.Name)
			}
			continue
		}
		// Each env var name carries exactly one token; two credentials
		// claiming it would leave the agent with only one of them.
		for _, name := range s.EnvNames() {
			if owner, taken := envNames[name]; taken {
				return nil, fmt.Errorf("credentials %q and %q both use env var %q", owner, s.Name, name)
			}
			envNames[name] = s.Name
		}
		// Deep copy: specs share slices with the package-level provider table.
		creds = append(creds, EgressCredential{EgressSecret: *s.DeepCopy(), SourceKey: k})
	}
	return creds, nil
}

// EnvNames returns the env var names the agent gets this credential's token
// under: Name followed by Aliases.
func (s *EgressSecret) EnvNames() []string {
	return append([]string{s.Name}, s.Aliases...)
}

// GetMatchHeaders returns the headers searched for the token, defaulting to
// Authorization.
func (s *EgressSecret) GetMatchHeaders() []string {
	if s == nil || len(s.MatchHeaders) == 0 {
		return []string{"Authorization"}
	}
	return s.MatchHeaders
}

// GetEgress returns the egress proxy configuration, if any.
func (h *HermesAgent) GetEgress() *Egress {
	return h.Spec.Egress
}

// GetEgressSecretName returns the name of the operator-managed Secret holding
// the rendered proxy.yaml and the agent's proxy tokens.
func (h *HermesAgent) GetEgressSecretName() string {
	return h.Name + "-egress"
}

// GetEgressCASecretName returns the name of the operator-managed CA Secret.
func (h *HermesAgent) GetEgressCASecretName() string {
	return h.Name + "-egress-ca"
}

// GetEgressCASource returns the Secret the iron-proxy CA is read from and its
// certificate and key data keys: the user-supplied Secret and the TLS keys
// when CA.SecretRef is set, the operator-managed Secret otherwise.
func (h *HermesAgent) GetEgressCASource() (secretName, certKey, keyKey string) {
	if ref := h.GetEgress().GetCASecretRefName(); ref != "" {
		return ref, EgressCATLSCertKey, EgressCATLSKeyKey
	}
	return h.GetEgressCASecretName(), EgressCAManagedCertKey, EgressCAManagedKeyKey
}

// GetEgressSourceSecretNames returns the user-supplied Secrets the egress
// proxy reads (credentials and CA), so that a change to either re-reconciles
// the agent.
func (h *HermesAgent) GetEgressSourceSecretNames() []string {
	e := h.GetEgress()
	if !e.IsEnabled() {
		return nil
	}
	var names []string
	for _, n := range []string{e.GetCredentialsSecretName(), e.GetCASecretRefName()} {
		if n != "" {
			names = append(names, n)
		}
	}
	return names
}

// ValidateEgressSecretRefs rejects user-supplied Secrets named like a Secret
// the operator manages for egress: the operator would overwrite the user's
// Secret, and could hand its real keys to the agent as proxy tokens.
func (h *HermesAgent) ValidateEgressSecretRefs() error {
	e := h.GetEgress()
	creds, ca := e.GetCredentialsSecretName(), e.GetCASecretRefName()
	switch {
	case creds != "" && (creds == h.GetEgressSecretName() || creds == h.GetEgressCASecretName()):
		return fmt.Errorf("egress credentials Secret %q collides with a Secret the operator manages", creds)
	case ca != "" && ca == h.GetEgressSecretName():
		return fmt.Errorf("egress CA Secret %q collides with a Secret the operator manages", ca)
	}
	return nil
}
