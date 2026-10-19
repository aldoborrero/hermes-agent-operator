package usecase

import (
	"context"
	"fmt"
	"maps"
	"slices"

	agentsv1alpha1 "hermeum/hermes-agent-operator/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// configMapDataEqual reports whether two ConfigMaps carry the same data, so
// reconcilers can skip no-op updates. It is shared by every ConfigMap
// reconciler instead of living in one resource's file.
func configMapDataEqual(a, b *corev1.ConfigMap) bool {
	return maps.Equal(a.Data, b.Data)
}

// resolveEgressCredentials resolves the credentials iron-proxy swaps against
// the keys of the egress credentials Secret, which must exist when it is
// referenced. It is shared by the egress Secret and StatefulSet reconcilers,
// which must agree on the credentials.
func (u *HermesAgentUseCase) resolveEgressCredentials(ctx context.Context, ha *agentsv1alpha1.HermesAgent) ([]agentsv1alpha1.EgressCredential, error) {
	eg := ha.GetEgress()
	var keys []string
	if name := eg.GetCredentialsSecretName(); name != "" {
		secret, err := u.kube.GetSecret(ctx, GetSecretParam{NamespacedName: types.NamespacedName{Name: name, Namespace: ha.Namespace}})
		if err != nil {
			return nil, err
		}
		if secret == nil {
			return nil, fmt.Errorf("egress credentials Secret %q not found", name)
		}
		keys = slices.Collect(maps.Keys(secret.Data))
	}
	return eg.ResolveCredentials(keys)
}
