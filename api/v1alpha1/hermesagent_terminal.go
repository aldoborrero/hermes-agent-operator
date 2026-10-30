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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// HermesTerminal configures the backend that runs the agent's shell commands.
type HermesTerminal struct {
	// kubernetes runs each shell command in a session pod created through the
	// Kubernetes API, instead of inside the hermes-agent container.
	// +optional
	Kubernetes *HermesTerminalKubernetes `json:"kubernetes,omitempty"`
}

// HermesTerminalKubernetes configures the Hermes `kubernetes` terminal backend.
//
// The fields mirror the agent's own `terminal.kubernetes` config block, and the
// operator writes them into the generated config.yaml. Anything already set
// under hermes.config.raw wins, so a raw block is always the escape hatch.
//
// Enabling this also makes the operator grant the session-pod RBAC to the
// agent's ServiceAccount, inject the downward-API pod identity, and isolate the
// session pods with their own NetworkPolicy — none of which the agent can do
// for itself.
type HermesTerminalKubernetes struct {
	// enabled selects the kubernetes terminal backend.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// namespace is where session pods are created. Empty means the agent's own
	// namespace, resolved by the agent from its projected ServiceAccount.
	//
	// A namespace other than the agent's is not managed by the operator: the
	// Role, RoleBinding and NetworkPolicy below are always created in the
	// agent's namespace, so cross-namespace RBAC and isolation are yours to
	// apply.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// podMetadata is the verbatim metadata of the session pod (labels,
	// annotations). The agent always owns name and namespace, and appends its
	// own ownerReference.
	// +optional
	PodMetadata *apiextensionsv1.JSON `json:"podMetadata,omitempty"`

	// podSpec is the verbatim PodSpec of the session pod. Left unset, the agent
	// applies its own documented default (an ephemeral ubuntu pod). A non-empty
	// value replaces that default wholesale — it is not merged.
	//
	// Free-form because it is a PodSpec the agent posts as written; re-typing it
	// here would only drift from the agent's schema.
	// +optional
	PodSpec *apiextensionsv1.JSON `json:"podSpec,omitempty"`

	// execContainerName is the container in podSpec that commands exec into.
	// It selects a container, it does not create one.
	// +kubebuilder:default="workspace"
	// +optional
	ExecContainerName string `json:"execContainerName,omitempty"`

	// ownedSelector are the labels marking a pod as this backend's. Empty means
	// the agent's default, {app.kubernetes.io/managed-by: hermes-agent}.
	//
	// The session-pod NetworkPolicy selects on these labels, so overriding them
	// moves both together.
	// +optional
	OwnedSelector map[string]string `json:"ownedSelector,omitempty"`

	// readyTimeoutSeconds is how long the agent waits for a session pod to
	// become Ready. Raise it for slow image pulls or sandboxed runtimes.
	// +kubebuilder:validation:Minimum=1
	// +optional
	ReadyTimeoutSeconds *int32 `json:"readyTimeoutSeconds,omitempty"`

	// ownerReference stamps the agent's own pod as the session pod's owner, so
	// session pods are garbage-collected when the agent pod is deleted.
	// "off" leaves them bounded only by podSpec.activeDeadlineSeconds.
	// +kubebuilder:validation:Enum=auto;off
	// +kubebuilder:default=auto
	// +optional
	OwnerReference string `json:"ownerReference,omitempty"`

	// trustedSandbox treats the session pod as a disposable boundary and skips
	// the dangerous-command approval layer. Set it false when podSpec grants
	// access to node-owned state (hostPath, hostNetwork/hostPID/hostIPC, or a
	// privileged container) and you want approvals back in the loop.
	// +optional
	TrustedSandbox *bool `json:"trustedSandbox,omitempty"`

	// rbac grants the agent's ServiceAccount the pod and pod/exec permissions
	// the backend needs, in the agent's namespace. Disable it to bind your own
	// Role — without those verbs every command fails.
	// +kubebuilder:default=true
	// +optional
	RBAC *bool `json:"rbac,omitempty"`

	// networkPolicy isolates the session pods. They are created by the agent,
	// not the operator, so the instance NetworkPolicy under security does not
	// select them.
	// +optional
	NetworkPolicy *SessionPodNetworkPolicy `json:"networkPolicy,omitempty"`
}

// SessionPodNetworkPolicy configures network isolation for terminal session pods.
type SessionPodNetworkPolicy struct {
	// enabled creates a default-deny NetworkPolicy selecting the session pods,
	// with egress to cluster DNS.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// allowInternet adds egress to everything outside excludedEgressCIDRs, so
	// sessions can reach package registries and git forges.
	// +kubebuilder:default=true
	// +optional
	AllowInternet *bool `json:"allowInternet,omitempty"`

	// excludedEgressCIDRs are the ranges allowInternet must not open. Defaults
	// to RFC1918 and link-local, which on most clusters covers the service and
	// pod networks. Add your node, API server or service ranges if they sit on
	// publicly routable addresses.
	// +optional
	ExcludedEgressCIDRs []string `json:"excludedEgressCIDRs,omitempty"`

	// There is deliberately no additionalEgress here, unlike under
	// security.networkPolicy. NetworkPolicies are additive: a second policy
	// selecting the same session pods contributes its egress rules to this
	// one, so the capability is a plain manifest away. Embedding a second copy
	// of NetworkPolicyEgressRule's schema costs ~28 KB of CRD, and this CRD is
	// already within a few KB of the 256 KiB ceiling that `kubectl apply` puts
	// on its last-applied-configuration annotation.
}

func (t *HermesTerminal) GetKubernetes() *HermesTerminalKubernetes {
	if t == nil {
		return nil
	}
	return t.Kubernetes
}

// IsEnabled reports whether the kubernetes terminal backend is active. A nil
// block means the backend was never requested.
func (k *HermesTerminalKubernetes) IsEnabled() bool {
	if k == nil {
		return false
	}
	if k.Enabled == nil {
		return true
	}
	return *k.Enabled
}

// ShouldManageRBAC reports whether the operator adds the session-pod rules to
// the managed Role.
func (k *HermesTerminalKubernetes) ShouldManageRBAC() bool {
	if !k.IsEnabled() {
		return false
	}
	if k.RBAC == nil {
		return true
	}
	return *k.RBAC
}

// GetNamespace returns where session pods are created. Empty means the agent's
// own namespace, which the agent resolves from its projected ServiceAccount.
func (k *HermesTerminalKubernetes) GetNamespace() string {
	if k == nil {
		return ""
	}
	return k.Namespace
}

func (k *HermesTerminalKubernetes) GetExecContainerName() string {
	if k == nil || k.ExecContainerName == "" {
		return defaultExecContainerName
	}
	return k.ExecContainerName
}

// GetOwnedSelector returns the labels marking a session pod as the backend's,
// falling back to the agent's own default.
func (k *HermesTerminalKubernetes) GetOwnedSelector() map[string]string {
	if k == nil || len(k.OwnedSelector) == 0 {
		return map[string]string{defaultOwnedSelectorKey: defaultOwnedSelectorValue}
	}
	return k.OwnedSelector
}

func (k *HermesTerminalKubernetes) GetNetworkPolicy() *SessionPodNetworkPolicy {
	if k == nil {
		return nil
	}
	return k.NetworkPolicy
}

// IsEnabled reports whether session pods get their own NetworkPolicy. It
// follows the backend: requesting the backend without saying otherwise means
// the session pods are isolated.
func (n *SessionPodNetworkPolicy) IsEnabled() bool {
	if n == nil || n.Enabled == nil {
		return true
	}
	return *n.Enabled
}

func (n *SessionPodNetworkPolicy) ShouldAllowInternet() bool {
	if n == nil || n.AllowInternet == nil {
		return true
	}
	return *n.AllowInternet
}

// GetExcludedEgressCIDRs returns the ranges allowInternet leaves closed.
func (n *SessionPodNetworkPolicy) GetExcludedEgressCIDRs() []string {
	if n == nil || len(n.ExcludedEgressCIDRs) == 0 {
		return defaultExcludedEgressCIDRs()
	}
	return n.ExcludedEgressCIDRs
}

const (
	defaultExecContainerName = "workspace"
	// Mirrors the agent's own default owned_selector.
	defaultOwnedSelectorKey   = "app.kubernetes.io/managed-by"
	defaultOwnedSelectorValue = "hermes-agent"
)

func defaultExcludedEgressCIDRs() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	}
}
