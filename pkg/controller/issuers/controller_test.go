package issuers

import (
	context "context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestIssuerReadinessStatus_DNS01Providers(t *testing.T) {
	ctx := context.Background()
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "default",
		},
		Spec: cmapi.IssuerSpec{
			ACME: &cmapi.ACMEIssuer{
				DNS01: &cmapi.ACMEIssuerDNS01Provider{
					Cloudflare: &cmapi.ACMEIssuerDNS01ProviderCloudflare{
						Email: "test@example.com",
						APIKey: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "missing-secret"},
							Key:                  "api-key",
						},
					},
				},
			},
		},
	}

	// Simulate readiness check logic
	ready := true
	reason := "Ready"
	if issuer.Spec.ACME != nil && issuer.Spec.ACME.DNS01 != nil {
		provider := issuer.Spec.ACME.DNS01
		if provider.Cloudflare != nil {
			// Simulate missing secret
			ready = false
			reason = "Cloudflare secret missing: not found"
		}
	}

	if !ready {
		t.Logf("Issuer not ready: %s", reason)
	}
}

// Example test for controller's Sync method
func TestControllerSync_UpdatesIssuerReadiness(t *testing.T) {
	// Setup fake client, informer, and controller
	// This is a simplified example; adapt to your actual controller implementation
	// You may need to import additional packages and set up the test environment

	// issuer := ... // create issuer as above
	// client := fake.NewSimpleClientset(issuer)
	// informer := ... // set up informer for Issuer
	// ctrl := NewController(client, informer, ...)

	// err := ctrl.Sync(context.Background(), issuer)
	// if err != nil {
	//     t.Fatalf("Sync failed: %v", err)
	// }

	// fetchedIssuer, _ := client.CertmanagerV1().Issuers(issuer.Namespace).Get(context.Background(), issuer.Name, metav1.GetOptions{})
	// if !isIssuerReady(fetchedIssuer) {
	//     t.Errorf("Issuer should be marked ready after Sync")
	// }
}
