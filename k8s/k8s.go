// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/open-ness/edgecontroller/uuid"
	"github.com/pkg/errors"
	appsV1 "k8s.io/api/apps/v1"
	autoscalingV1 "k8s.io/api/autoscaling/v1"
	apiV1 "k8s.io/api/core/v1"
	networkingV1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restClient "k8s.io/client-go/rest"
)

// App contains the information for deploying an application with
// Kubernetes.
type App struct {
	ID     string
	Cores  int
	Memory int // in MB
	Image  string
	Ports  []*PortProto
}

// PortProto is a port and protocol tuple
type PortProto struct {
	Port     int32
	Protocol string
}

const (
	// Key for the label attached to a k8s pod or k8s node containing the Node ID
	nodeIDLabelKey = "node-id"
	// Key for the label attached to a k8s pod containing the App ID
	appIDLabelKey = "app-id"
)

// Client abstracts calls to k8s master API
type Client struct {
	// Host must be a host string, a host:port pair, or a URL to the base of the apiserver.
	// If a URL is given then the (optional) Path of that URL represents a prefix that must
	// be appended to all request URIs used to access the apiserver. This allows a frontend
	// proxy to easily relocate all of the apiserver endpoints.
	Host string

	// APIPath is a sub-path that points to an API root.
	APIPath string

	// Authentication info
	Username string
	CertFile string
	KeyFile  string
	CAFile   string

	// ImagePullPolicy specifies container retrieval policy. If not provided,
	// PullNever policy will be used. This field is intended for overriding default
	// policy for testing.
	ImagePullPolicy apiV1.PullPolicy

	// NewClientSet creates a new Kubernetes clientset interface. If it is nil,
	// a REST client with TLS will be used. This field is intended for use
	// mocking an external connection.
	NewClientSet func() (kubernetes.Interface, error)

	connectOnce sync.Once
	clientSet   kubernetes.Interface
	err         error
}

// Ping checks the connection to the Kubernetes server.
func (ks *Client) Ping() error {
	ks.connectOnce.Do(ks.init)
	if ks.err != nil {
		return ks.err
	}
	return ks.clientSet.CoreV1().RESTClient().Get().AbsPath("/").Do().Error()
}

func (ks *Client) init() {
	// default image pull policy is never pull the image, only use the local image provided
	if ks.ImagePullPolicy == "" {
		ks.ImagePullPolicy = apiV1.PullNever
	}

	csCreate := ks.NewClientSet
	if csCreate == nil {
		csCreate = func() (kubernetes.Interface, error) {
			return kubernetes.NewForConfig(
				&restClient.Config{
					Host:     ks.Host,
					APIPath:  ks.APIPath,
					Username: ks.Username,
					TLSClientConfig: restClient.TLSClientConfig{
						Insecure: false,
						CertFile: ks.CertFile,
						KeyFile:  ks.KeyFile,
						CAFile:   ks.CAFile,
					},
				},
			)
		}
	}
	ks.clientSet, ks.err = csCreate()
}

// Deploy creates a kubernetes deployment
func (ks *Client) Deploy(ctx context.Context, nodeID string, app App) error {
	ks.connectOnce.Do(ks.init)
	if ks.err != nil {
		return ks.err
	}
	// initial checks
	if err := ks.checkNode(nodeID); err != nil {
		return errors.Wrap(err, "deploy: node available error")
	}
	// make the deployment to the correct node
	if err := ks.deploy(nodeID, app); err != nil {
		return errors.Wrap(err, "deploy: deployment error")
	}
	return nil
}

// Undeploy cascade deletes a kubernetes deployment
func (ks *Client) Undeploy(ctx context.Context, nodeID, appID string) error {
	ks.connectOnce.Do(ks.init)
	if ks.err != nil {
		return ks.err
	}
	// make the deployment to the correct node
	if err := ks.undeploy(nodeID, appID); err != nil {
		return errors.Wrap(err, "undeploy: un-deployment error")
	}
	return nil
}

// Check if a node is available for the deployment. THIS IS A SANITY CHECK.
func (ks *Client) checkNode(nodeID string) error {
	nodeList, err := ks.clientSet.CoreV1().Nodes().List(
		metaV1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", nodeIDLabelKey, nodeID),
		},
	)
	if err != nil {
		return errors.Wrap(err, "get kubernetes node list error")
	}
	if len(nodeList.Items) != 1 {
		return errors.Wrap(err, "no nodes or duplicate nodes detected")
	}
	return nil
}

// create a kubernetes deployment
func (ks *Client) deploy(nodeID string, app App) error {
	protoConverter := map[string]apiV1.Protocol{
		"tcp":  apiV1.ProtocolTCP,
		"udp":  apiV1.ProtocolUDP,
		"sctp": apiV1.ProtocolSCTP,
	}

	var ports []apiV1.ContainerPort
	for _, portProt := range app.Ports {
		proto, ok := protoConverter[portProt.Protocol]
		if !ok {
			return errors.New("unsupported protocol for kubernetes error")
		}
		ports = append(ports, apiV1.ContainerPort{
			ContainerPort: portProt.Port,
			Protocol:      proto,
		})
	}

	// deployment client
	deploymentsClient := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault)
	_, err := deploymentsClient.Create(&appsV1.Deployment{
		ObjectMeta: metaV1.ObjectMeta{
			GenerateName: "app",
			Labels: map[string]string{
				appIDLabelKey:  app.ID,
				nodeIDLabelKey: nodeID,
			},
		},
		Spec: appsV1.DeploymentSpec{
			// only creates a deployment. no replicas created,
			// to be consistent with docker native deploy
			Replicas: int32Ptr(0),
			// Must match Template.ObjectMeta.Labels according to
			// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#deploymentspec-v1-apps
			Selector: &metaV1.LabelSelector{
				MatchLabels: map[string]string{
					appIDLabelKey:  app.ID,
					nodeIDLabelKey: nodeID,
				},
			},
			Strategy: appsV1.DeploymentStrategy{
				Type: appsV1.RecreateDeploymentStrategyType,
			},
			Template: apiV1.PodTemplateSpec{
				ObjectMeta: metaV1.ObjectMeta{
					Labels: map[string]string{
						appIDLabelKey:  app.ID,
						nodeIDLabelKey: nodeID,
					},
				},
				Spec: apiV1.PodSpec{
					Containers: []apiV1.Container{
						{
							Resources: apiV1.ResourceRequirements{
								Limits: apiV1.ResourceList{
									// CPU, in cores. (500m = .5 cores)
									apiV1.ResourceCPU: *resource.NewQuantity(
										int64(app.Cores),
										resource.DecimalSI,
									),

									// Memory, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
									apiV1.ResourceMemory: *resource.NewQuantity(
										int64(1024*1024*app.Memory),
										resource.BinarySI,
									),

									// Volume size, in bytes (e,g. 5Gi = 5GiB = 5 * 1024 * 1024 * 1024)
									// apiV1.ResourceStorage: resource.MustParse(d.Storage),

									// Local ephemeral storage, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
									// The resource name for ResourceEphemeralStorage is alpha and it can change
									// across releases.
									// apiV1.ResourceEphemeralStorage: resource.MustParse(d.EphemeralStorage),
								},
							},
							Name:            uuid.New(),
							Image:           app.ID,
							Ports:           ports,
							ImagePullPolicy: ks.ImagePullPolicy,
							SecurityContext: &apiV1.SecurityContext{
								Capabilities: &apiV1.Capabilities{
									Add: []apiV1.Capability{"NET_ADMIN"},
								},
							},
						},
					},
					NodeSelector: map[string]string{
						nodeIDLabelKey: nodeID,
					},
				},
			},
		},
	})
	if err != nil {
		return errors.Wrap(err, "create kubernetes deployment error")
	}
	return nil
}

// delete a kubernetes deployment
func (ks *Client) undeploy(nodeID, appID string) error {
	deploymentName, err := ks.getDeploymentName(nodeID, appID)
	if err != nil {
		return errors.Wrap(err, "start: error getting deployment name by ID")
	}

	deploymentsClient := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault)
	foreground := metaV1.DeletePropagationForeground
	err = deploymentsClient.Delete(deploymentName, &metaV1.DeleteOptions{
		PropagationPolicy: &foreground,
	})
	return errors.Wrap(err, "create kubernetes deployment error")
}

func int32Ptr(i int32) *int32 { return &i }

// Start scales up the number of replicas of kubernetes deployment to 1.
func (ks *Client) Start(ctx context.Context, nodeID, appID string) error {
	deploymentName, err := ks.getDeploymentName(nodeID, appID)
	if err != nil {
		return errors.Wrap(err, "start: error getting deployment name by ID")
	}

	deploymentsClient := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault)
	_, err = deploymentsClient.UpdateScale(
		deploymentName,
		&autoscalingV1.Scale{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      deploymentName,
				Namespace: apiV1.NamespaceDefault,
			},
			Spec: autoscalingV1.ScaleSpec{Replicas: 1},
		})
	return errors.Wrap(err, "start: error scaling deployment to 1 replica")
}

// Stop scales down the number of replicas of kubernetes deployment to 0.
func (ks *Client) Stop(ctx context.Context, nodeID, appID string) error {
	deploymentName, err := ks.getDeploymentName(nodeID, appID)
	if err != nil {
		return errors.Wrap(err, "stop: error getting deployment name by ID")
	}

	deploymentsClient := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault)
	_, err = deploymentsClient.UpdateScale(
		deploymentName,
		&autoscalingV1.Scale{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      deploymentName,
				Namespace: apiV1.NamespaceDefault,
			},
			Spec: autoscalingV1.ScaleSpec{Replicas: 0},
		})
	return errors.Wrap(err, "stop: error scaling deployment to 0 replicas")
}

// Restart scales down the number of replicas of kubernetes deployment to 0 and then scale up to 1.
func (ks *Client) Restart(ctx context.Context, nodeID, appID string) error {
	deploymentName, err := ks.getDeploymentName(nodeID, appID)
	if err != nil {
		return errors.Wrap(err, "restart: error getting deployment name by ID")
	}

	deploymentsClient := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault)

	// Scale down to 0
	_, err = deploymentsClient.UpdateScale(
		deploymentName,
		&autoscalingV1.Scale{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      deploymentName,
				Namespace: apiV1.NamespaceDefault,
			},
			Spec: autoscalingV1.ScaleSpec{Replicas: 0},
		},
	)
	if err != nil {
		return errors.Wrap(err, "restart: error scaling deployment to 0 replicas")
	}

	// Scale up to 1
	_, err = deploymentsClient.UpdateScale(
		deploymentName,
		&autoscalingV1.Scale{
			ObjectMeta: metaV1.ObjectMeta{
				Name:      deploymentName,
				Namespace: apiV1.NamespaceDefault,
			},
			Spec: autoscalingV1.ScaleSpec{Replicas: 1},
		},
	)
	return errors.Wrap(err, "restart: error scaling deployment to 1 replica")
}

// get unique generated deployment name by controller deployment ID
func (ks *Client) getDeploymentName(nodeID, appID string) (string, error) {
	deployment, err := ks.getDeployment(nodeID, appID)
	if err != nil {
		return "", err
	}
	return deployment.ObjectMeta.Name, nil
}

// get deployment info by controller deployment ID
func (ks *Client) getDeployment(nodeID, appID string) (*appsV1.Deployment, error) {
	deployments, err := ks.clientSet.AppsV1().Deployments(apiV1.NamespaceDefault).
		List(metaV1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s,%s=%s", appIDLabelKey, appID, nodeIDLabelKey, nodeID),
		})
	if err != nil {
		return nil, errors.Wrap(err, "error getting list of deployments")
	}

	deps := deployments.Items
	if len(deps) == 0 {
		return nil, errors.New("deployment not found")
	}
	if len(deps) > 1 {
		return nil, errors.New("more than one deployment found")
	}

	return &deps[0], nil
}

func getPodStatus(pod apiV1.Pod) LifecycleStatus {
	if pod.DeletionTimestamp != nil {
		return Terminating
	}

	// Capture situation when container did not start because of e.g. ErrImageNeverPull
	for _, cStatus := range pod.Status.ContainerStatuses {
		if cStatus.State.Waiting != nil {
			if strings.HasPrefix(cStatus.State.Waiting.Reason, "Err") {
				return Error
			}

			if strings.Contains(cStatus.State.Waiting.Reason, "ContainerCreating") {
				return Starting
			}
		}
	}

	switch pod.Status.Phase {
	case apiV1.PodPending:
		return Pending
	case apiV1.PodRunning:
		return Running
	}

	return Unknown
}

// Status gets the status of kubernetes app
func (ks *Client) Status(ctx context.Context, nodeID, appID string) (LifecycleStatus, error) {
	// Check if deployment actually exists
	_, err := ks.getDeployment(nodeID, appID)
	if err != nil {
		return Error, err
	}

	podsClient := ks.clientSet.CoreV1().Pods(apiV1.NamespaceDefault)

	listOptions := metaV1.ListOptions{
		LabelSelector: fmt.Sprintf("node-id=%s,app-id=%s", nodeID, appID),
	}

	pods, err := podsClient.List(listOptions)
	if err != nil {
		return Unknown, err
	}

	if len(pods.Items) == 0 {
		// Deployment exists, but no pod is running
		return Deployed, nil
	}

	if len(pods.Items) == 1 {
		// Just one pod for deployment
		return getPodStatus(pods.Items[0]), nil
	}

	// Many pods exist
	state := Unknown
	isAnyTerminating := false
	for _, pod := range pods.Items {
		if getPodStatus(pod) == Terminating {
			isAnyTerminating = true
			continue
		}

		state = getPodStatus(pod)
	}

	if state == Unknown && isAnyTerminating {
		return Terminating, nil
	}

	return state, nil
}

// GetAppIDByIP gets the ID of an application running on a node by its pod IP address
func (ks *Client) GetAppIDByIP(ctx context.Context, nodeID, ipAddr string) (string, error) {
	pods, err := ks.clientSet.CoreV1().Pods(apiV1.NamespaceDefault).List(
		metaV1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", nodeIDLabelKey, nodeID),
		},
	)
	if err != nil {
		return "", errors.Wrapf(err, "error getting pods on node %s", nodeID)
	}

	for _, pod := range pods.Items {
		if pod.Status.PodIP == ipAddr {
			val, ok := pod.GetLabels()[appIDLabelKey]
			if !ok {
				return "", errors.Errorf("pod with IP '%s' missing required deployment label(s)", ipAddr)
			}
			return val, nil
		}
	}

	return "", errors.Errorf("no pod found with IP '%s'", ipAddr)
}

// ApplyNetworkPolicy applies network policy for app on specified node
func (ks *Client) ApplyNetworkPolicy(ctx context.Context,
	nodeID, appID string, policy *networkingV1.NetworkPolicy) error {

	networkingClient := ks.clientSet.NetworkingV1().RESTClient()

	// Currently only 1 NetworkPolicy per app so we can just concatenate node and app
	policy.ObjectMeta.Name = fmt.Sprintf("np-%s.%s", nodeID, appID)

	policy.Spec.PodSelector = metaV1.LabelSelector{
		MatchLabels: map[string]string{
			"app-id":  appID,
			"node-id": nodeID,
		},
	}

	err := networkingClient.Post().
		Context(ctx).
		Namespace(apiV1.NamespaceDefault).
		Resource("networkpolicies").
		Body(policy).
		Do().Error()

	if err != nil {
		return errors.Wrap(err, "failed to create network policy")
	}

	return nil
}

// DeleteNetworkPolicy deletes network policy for app on specified node
func (ks *Client) DeleteNetworkPolicy(ctx context.Context, nodeID, appID string) error {
	networkingClient := ks.clientSet.NetworkingV1().RESTClient()

	propagation := metaV1.DeletePropagationBackground
	gracePeriodSeconds := int64(0)
	deleteOptions := &metaV1.DeleteOptions{
		PropagationPolicy:  &propagation,
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	name := fmt.Sprintf("np-%s.%s", nodeID, appID)

	err := networkingClient.Delete().
		Context(ctx).
		Namespace(apiV1.NamespaceDefault).
		Resource("networkpolicies").
		Name(name).
		Body(deleteOptions).
		Do().Error()

	if err != nil {
		return errors.Wrap(err, "failed to delete network policy")
	}

	return nil
}

// GetNetworkPolicy returns network policy for app on specified node
func (ks *Client) GetNetworkPolicy(ctx context.Context, nodeID, appID string) (*networkingV1.NetworkPolicy, error) {
	networkingClient := ks.clientSet.NetworkingV1().NetworkPolicies(apiV1.NamespaceDefault)

	name := fmt.Sprintf("np-%s.%s", nodeID, appID)

	netpol, err := networkingClient.Get(name, metaV1.GetOptions{})

	return netpol, err
}
