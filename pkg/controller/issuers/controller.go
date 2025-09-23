/*
Copyright 2020 The cert-manager Authors.

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

package issuers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type controller struct {
	issuerLister cmlisters.IssuerLister
	secretLister internalinformers.SecretLister

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// logger to be used by this controller
	log logr.Logger

	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// issuerFactory is used to obtain a reference to the Issuer implementation
	// for each ClusterIssuer resource
	issuerFactory issuer.Factory

	// fieldManager is the manager name used for the Apply operations.
	fieldManager string

	// Periodic check ticker.
	periodicCheckInterval time.Duration
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context, periodicCheckInterval time.Duration) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultItemBasedRateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	// obtain references to all the informers used by this controller
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
	secretInformer := ctx.KubeSharedInformerFactory.Secrets()
	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		issuerInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.issuerLister = issuerInformer.Lister()
	c.secretLister = secretInformer.Lister()

	// register handler functions
	if _, err := issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}
	if _, err := secretInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: c.secretEvent}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	// instantiate additional helpers used by this controller
	c.issuerFactory = issuer.NewFactory(ctx)
	c.cmClient = ctx.CMClient
	c.fieldManager = ctx.FieldManager
	c.recorder = ctx.Recorder

	// Set periodic check interval (configurable)
	if periodicCheckInterval > 0 {
		c.periodicCheckInterval = periodicCheckInterval
	} else {
		c.periodicCheckInterval = time.Hour
	}

	// Add periodic readiness check
	ctx.RunDurationFuncs = append(ctx.RunDurationFuncs, controllerpkg.RunDurationFunc{
		Fn: func(ctx context.Context) {
			c.periodicReadinessCheck(ctx)
		},
		Duration: c.periodicCheckInterval,
	})

	return c.queue, mustSync, nil
}

// periodicReadinessCheck enqueues all issuers for readiness validation
func (c *controller) periodicReadinessCheck(ctx context.Context) {
	issuers, err := c.issuerLister.List(labels.Everything())
	if err != nil {
		c.log.Error(err, "failed to list issuers for periodic readiness check")
		return
	}
	for _, iss := range issuers {
		c.queue.Add(types.NamespacedName{
			Name:      iss.Name,
			Namespace: iss.Namespace,
		})
	}
}

// TODO: replace with generic handleObject function (like Navigator)
func (c *controller) secretEvent(obj interface{}) {
	log := c.log.WithName("secretEvent")
	secret, ok := controllerpkg.ToSecret(obj)
	if !ok {
		log.Error(nil, "object is not a secret", "object", obj)
		return
	}

	log = logf.WithResource(log, secret)
	issuers, err := c.issuersForSecret(secret)
	if err != nil {
		log.Error(err, "error looking up issuers observing secret")
		return
	}
	for _, iss := range issuers {
		c.queue.Add(types.NamespacedName{
			Name:      iss.Name,
			Namespace: iss.Namespace,
		})
	}
}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx)
	namespace, name := key.Namespace, key.Name

	issuer, err := c.issuerLister.Issuers(namespace).Get(name)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}
	if issuer == nil || issuer.DeletionTimestamp != nil {
		// If the Issuer object was/ is being deleted, we don't want to update its status.
		return nil
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, issuer))

	// Check issuer readiness using extracted method
	ready, reason := c.checkIssuerReadiness(ctx, issuer)
	if !ready {
		// TODO: update Issuer status to Not Ready with reason
			_, err := c.secretLister.Secrets(issuer.Namespace).Get(provider.Cloudflare.APIKey.Name)
		// Example: record event
		c.recorder.Event(issuer, "Warning", "NotReady", reason)
	}

	return c.Sync(ctx, issuer)
}

// checkIssuerReadiness checks if the given issuer is ready and returns a boolean and a reason string.
func (c *controller) checkIssuerReadiness(ctx context.Context, issuer *v1.Issuer) (bool, string) {
				// Placeholder for dummy API call: list zones
				// NOTE: Actual API call using provider credentials is not yet implemented.
				// TODO: implement actual call using provider credentials
	reason := "Ready"

	// Example: check for ACME DNS01 provider
	if issuer.Spec.ACME != nil && issuer.Spec.ACME.DNS01 != nil {
		provider := issuer.Spec.ACME.DNS01
		// Cloudflare
		if provider.Cloudflare != nil {
			_, err := c.secretLister.Secrets(namespace).Get(provider.Cloudflare.APIKey.Name)
			if err != nil {
				ready = false
				reason = "Cloudflare secret missing: " + err.Error()
			}
		}
		// Route53
		if provider.Route53 != nil {
			// TODO: implement secret/key check and dummy API call
		}
		// Akamai
		if provider.Akamai != nil {
			// TODO: implement secret/key check and dummy API call
		}
		// AzureDNS
		if provider.AzureDNS != nil {
			// TODO: implement secret/key check and dummy API call
		}
		// DigitalOcean
		if provider.DigitalOcean != nil {
			// TODO: implement secret/key check and dummy API call
		}
		// CloudDNS
		if provider.CloudDNS != nil {
			// TODO: implement secret/key check and dummy API call
		}
		// AcmeDNS
		if provider.AcmeDNS != nil {
			// TODO: implement secret/key check and dummy API call
		}
	}

	return ready, reason
}

const (
	ControllerName = "issuers"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		// You can make the interval configurable via an environment variable or config here
		interval := time.Hour // default value
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{}).
			WithRegisterFunc(func(c controllerpkg.Interface, ctx *controllerpkg.Context) error {
				_, _, err := c.(*controller).Register(ctx, interval)
				return err
			}).
			Complete()
	})
}
