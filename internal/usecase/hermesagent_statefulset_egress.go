package usecase

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"

	agentsv1alpha1 "hermeum/hermes-agent-operator/api/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	egressContainerName = "iron-proxy"
	egressConfigVolume  = "egress-config"
	egressAgentCAVolume = "egress-agent-ca"
	// egressAgentCADir is where the agent container mounts the CA certificate,
	// never the key, to trust iron-proxy's MITM certificates.
	egressAgentCADir = "/etc/hermes-egress"
	// egressNoProxy keeps in-pod and in-cluster traffic, including the
	// Kubernetes API reached by IP, off the proxy.
	egressNoProxy = "localhost,127.0.0.1,.svc,.cluster.local,$(KUBERNETES_SERVICE_HOST)"
)

// egressPodInputs reads what the egress wiring needs beyond the spec: the
// resolved credentials, and a hash of the CA certificate and the egress Secret
// so that rotating either restarts the pod, which reads both only at start.
func (u *HermesAgentUseCase) egressPodInputs(ctx context.Context, ha *agentsv1alpha1.HermesAgent) ([]agentsv1alpha1.EgressCredential, string, error) {
	creds, err := u.resolveEgressCredentials(ctx, ha)
	if err != nil {
		return nil, "", err
	}

	caName, caCertKey, _ := ha.GetEgressCASource()
	h := sha256.New()
	for _, src := range []struct{ name, onlyKey string }{
		{caName, caCertKey},
		{ha.GetEgressSecretName(), ""},
	} {
		secret, err := u.kube.GetSecret(ctx, GetSecretParam{NamespacedName: types.NamespacedName{Name: src.name, Namespace: ha.Namespace}})
		if err != nil {
			return nil, "", err
		}
		if secret == nil {
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(secret.Data)) {
			if src.onlyKey == "" || k == src.onlyKey {
				_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", src.name, k, secret.Data[k])
			}
		}
	}
	return creds, fmt.Sprintf("%x", h.Sum(nil))[:16], nil
}

// buildEgressContainerSecurityContext returns a hardened security context for
// the iron-proxy container. Every listener binds an unprivileged loopback
// port, so no capability is needed.
func buildEgressContainerSecurityContext() *corev1.SecurityContext {
	ape := false
	rot := true
	uid := int64(65532)
	rofs := true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &ape,
		RunAsNonRoot:             &rot,
		RunAsUser:                &uid,
		RunAsGroup:               &uid,
		ReadOnlyRootFilesystem:   &rofs,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// buildEgressContainer adds the iron-proxy sidecar and routes the agent's
// outbound HTTP(S) through it. Each credential's real value is read into the
// sidecar's env from the credentials Secret; the agent gets the credential's
// proxy token under the same env var name, and its aliases, instead. Those
// env entries are appended last, so they shadow a real key reaching the agent
// through spec.hermes.envFrom or spec.hermes.env.
func buildEgressContainer(ha *agentsv1alpha1.HermesAgent, sts *appsv1.StatefulSet, creds []agentsv1alpha1.EgressCredential, inputsHash string) *appsv1.StatefulSet {
	sts = sts.DeepCopy()

	eg := ha.GetEgress()
	if !eg.IsEnabled() {
		return sts
	}

	caName, caCertKey, caKeyKey := ha.GetEgressCASource()
	agentCAPath := egressAgentCADir + "/" + agentsv1alpha1.EgressCAManagedCertKey

	if sts.Spec.Template.Annotations == nil {
		sts.Spec.Template.Annotations = map[string]string{}
	}
	sts.Spec.Template.Annotations[domain+"/egress-hash"] = inputsHash

	if c := findContainer(sts, hermesContainerName); c != nil {
		for _, kv := range [][2]string{
			{"HTTPS_PROXY", eg.GetHTTPSProxyURL()},
			{"https_proxy", eg.GetHTTPSProxyURL()},
			{"HTTP_PROXY", eg.GetHTTPProxyURL()},
			{"http_proxy", eg.GetHTTPProxyURL()},
			{"NO_PROXY", egressNoProxy},
			{"no_proxy", egressNoProxy},
			{"SSL_CERT_FILE", agentCAPath},
			{"REQUESTS_CA_BUNDLE", agentCAPath},
			{"NODE_EXTRA_CA_CERTS", agentCAPath},
			{"GIT_SSL_CAINFO", agentCAPath},
		} {
			c.Env = append(c.Env, corev1.EnvVar{Name: kv[0], Value: kv[1]})
		}
		for _, cred := range creds {
			token := &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: ha.GetEgressSecretName()},
				Key:                  cred.Name,
			}}
			for _, name := range append([]string{cred.Name}, cred.Aliases...) {
				c.Env = append(c.Env, corev1.EnvVar{Name: name, ValueFrom: token})
			}
		}
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
			Name:      egressAgentCAVolume,
			MountPath: egressAgentCADir,
			ReadOnly:  true,
		})
	}

	env := make([]corev1.EnvVar, 0, len(creds))
	for _, cred := range creds {
		env = append(env, corev1.EnvVar{
			Name: cred.Name,
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: eg.GetCredentialsSecretName()},
				Key:                  cred.SourceKey,
			}},
		})
	}

	sts.Spec.Template.Spec.Containers = append(sts.Spec.Template.Spec.Containers, corev1.Container{
		Name:            egressContainerName,
		Image:           eg.GetImage(),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            []string{"-config", agentsv1alpha1.EgressConfigDir + "/" + agentsv1alpha1.EgressProxyConfigKey},
		Env:             env,
		Resources:       eg.GetResources(),
		SecurityContext: buildEgressContainerSecurityContext(),
		VolumeMounts: []corev1.VolumeMount{
			{Name: egressConfigVolume, MountPath: agentsv1alpha1.EgressConfigDir, ReadOnly: true},
		},
	})

	defaultMode := int32(0o444)
	sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes,
		corev1.Volume{
			// Sidecar side: proxy.yaml plus the CA certificate and key, under
			// the fixed names proxy.yaml refers to.
			Name: egressConfigVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: ha.GetEgressSecretName()},
							Items:                []corev1.KeyToPath{{Key: agentsv1alpha1.EgressProxyConfigKey, Path: agentsv1alpha1.EgressProxyConfigKey}},
						}},
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: caName},
							Items: []corev1.KeyToPath{
								{Key: caCertKey, Path: agentsv1alpha1.EgressCAManagedCertKey},
								{Key: caKeyKey, Path: agentsv1alpha1.EgressCAManagedKeyKey},
							},
						}},
					},
				},
			},
		},
		corev1.Volume{
			// Agent side: the CA certificate only, never its key.
			Name: egressAgentCAVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  caName,
					Items:       []corev1.KeyToPath{{Key: caCertKey, Path: agentsv1alpha1.EgressCAManagedCertKey}},
					DefaultMode: &defaultMode,
				},
			},
		},
	)

	return sts
}
