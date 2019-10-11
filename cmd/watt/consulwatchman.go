package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	consulapi "github.com/hashicorp/consul/api"

	"github.com/datawire/ambassador/pkg/consulwatch"
	"github.com/datawire/ambassador/pkg/supervisor"
	"github.com/datawire/ambassador/pkg/watt"
)

const (
	distLockKey = "AMB_CONSUL_CONNECT_LEADER"
)

const (
	// envAmbassadorID creates a secret for a specific instance of an Ambassador API Gateway. The TLS secret name will
	// be formatted as "$AMBASSADOR_ID-consul-connect."
	envAmbassadorID = "_AMBASSADOR_ID"

	// envConsulAPIHost is the IP address or DNS name of the Consul Agent's HTTP API server.
	envConsulAPIHost = "_CONSUL_HOST"

	// envConsulAPIPort is the Port number of the Consul Agent's HTTP API server.
	envConsulAPIPort = "_CONSUL_PORT"

	// envSecretName is the full name of the Kubernetes Secret that contains the TLS certificate provided
	// by Consul. If this value is set then the value of AMBASSADOR_ID is ignored when the name of the TLS secret is
	// computed.
	envSecretName = "_AMBASSADOR_TLS_SECRET_NAME"

	// envSecretNamespace sets the namespace where the TLS secret is created.
	envSecretNamespace = "_AMBASSADOR_TLS_SECRET_NAMESPACE"
)

const (
	secretTemplate = `---
kind: Secret
apiVersion: v1
metadata:
    name: "%s"
type: "kubernetes.io/tls"
data:
    tls.crt: "%s"
    tls.key: "%s"
`
)

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

type agent struct {
	// AmbassadorID is the ID of the Ambassador instance.
	AmbassadorID string

	// The Agent registers a Consul Service when it starts and then fetches the leaf TLS certificate from the Consul
	// HTTP API with this name.
	ConsulServiceName string

	// SecretNamespace is the Namespace where the TLS secret is managed.
	SecretNamespace string

	// SecretName is the Name of the TLS secret managed by this agent.
	SecretName string

	// consulAPI is the client used to communicate with the Consul HTTP API server.
	consul *consulapi.Client
}

func newAgent(ambassadorID string, secretNamespace string, secretName string, consul *consulapi.Client) *agent {
	consulServiceName := "ambassador"
	if ambassadorID != "" {
		consulServiceName += "-" + ambassadorID
	}

	if secretName == "" {
		secretName = consulServiceName + "-consul-connect"
	}

	return &agent{
		AmbassadorID:      consulServiceName,
		SecretNamespace:   secretNamespace,
		SecretName:        secretName,
		ConsulServiceName: consulServiceName,
		consul:            consul,
	}
}

type consulEvent struct {
	WatchId   string
	Endpoints consulwatch.Endpoints
}

type consulwatchman struct {
	WatchMaker IConsulWatchMaker
	watchesCh  <-chan []ConsulWatchSpec
	watched    map[string]*supervisor.Worker
}

type ConsulWatchMaker struct {
	aggregatorCh chan<- consulEvent
}

// MakeConsulWatch does several things:
// - watches Consul and sends events to the aggregator channel
// - retrieves the TLS certificate issued by the Consul CA and stores it as a Kubernetes secret Ambassador will use to authenticate with upstream services.
func (m *ConsulWatchMaker) MakeConsulWatch(spec ConsulWatchSpec) (*supervisor.Worker, error) {
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = spec.ConsulAddress

	// TODO: Should we really allocated a Consul client per Service watch? Not sure... there some design stuff here
	// May be multiple consul clusters
	// May be different connection parameters on the consulConfig
	// Seems excessive...
	consul, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}

	// TODO(alvaro): this shold be obtained from a custom resource
	agent := newAgent(os.Getenv(envAmbassadorID), os.Getenv(envSecretNamespace), os.Getenv(envSecretName), consul)

	worker := &supervisor.Worker{
		Name: fmt.Sprintf("consul:%s", spec.WatchId()),
		Work: func(p *supervisor.Process) error {

			d, err := watt.NewDistLock(consul, distLockKey, 1*time.Minute)
			if err != nil {
				log.Fatalln(err)
			}

			caRootWatcher, err := consulwatch.NewConnectCARootsWatcher(consul, logger)
			if err != nil {
				log.Fatalln(err)
			}

			log.Printf("Watching CA leaf for %s\n", agent.ConsulServiceName)
			leafWatcher, err := consulwatch.NewConnectLeafWatcher(consul, logger, agent.ConsulServiceName)

			caRootChanged := make(chan *consulwatch.CARoots)
			leafChanged := make(chan *consulwatch.Certificate)

			caRootWatcher.Watch(func(roots *consulwatch.CARoots, e error) {
				if e != nil {
					p.Logf("Error watching root CA: %v\n", err)
				}

				caRootChanged <- roots
			})
			leafWatcher.Watch(func(certificate *consulwatch.Certificate, e error) {
				if e != nil {
					p.Logf("Error watching certificates: %v\n", err)
				}

				leafChanged <- certificate
			})

			eventsWatcher, err := consulwatch.New(consul, logger, spec.Datacenter, spec.ServiceName, true)
			if err != nil {
				p.Logf("failed to setup new consul watch %v", err)
				return err
			}

			eventsWatcher.Watch(func(endpoints consulwatch.Endpoints, e error) {
				endpoints.Id = spec.Id
				m.aggregatorCh <- consulEvent{spec.WatchId(), endpoints}
			})

			_ = p.Go(func(p *supervisor.Process) error {
				x := eventsWatcher.Start()
				if x != nil {
					p.Logf("failed to start service watcher %v", x)
					return x
				}

				return nil
			})

			acquireCh := make(chan bool)
			releaseCh := make(chan bool)
			for {
				// loop is to re-attempt for lock acquisition when
				// the lock was initially acquired but auto released after some time
				go d.RetryLockAcquire(acquireCh, releaseCh)

				select {
				case <-acquireCh:
					_ = p.Go(func(p *supervisor.Process) error {
						var caRoot *consulwatch.CARoot
						var leafCert *consulwatch.Certificate

						// wait for root CA and certificates, and update the
						// copy in Kubernetes when we get a new version
						for {
							select {
							case cert := <-caRootChanged:
								temp := cert.Roots[cert.ActiveRootID]
								caRoot = &temp
							case cert := <-leafChanged:
								leafCert = cert
							}

							if caRoot != nil && leafCert != nil {
								chain := createCertificateChain(caRoot.PEM, leafCert.PEM)
								secret := formatKubernetesSecretYAML(agent.SecretName, chain, leafCert.PrivateKeyPEM)

								err := applySecret(agent.SecretNamespace, secret)
								if err != nil {
									p.Log(err)
									continue
								}

								p.Logf("Updating TLS certificate secret: namespace=%s, secret=%s", agent.SecretNamespace, agent.SecretName)
							}
						}
					})
					_ = p.Go(func(p *supervisor.Process) error {
						err := leafWatcher.Start()
						if err != nil {
							p.Logf("failed to start service watcher %v", err)
							return err
						}
						return nil
					})
					_ = p.Go(func(p *supervisor.Process) error {
						err := caRootWatcher.Start()
						if err != nil {
							p.Logf("failed to start service watcher %v", err)
							return err
						}
						return nil
					})

				case <-releaseCh:
					p.Logf("Stopping Consul Connect watchers...")
					caRootWatcher.Stop()
					leafWatcher.Stop()
					// we will iterate and try to adquire the lock again...

				case <-p.Shutdown():
					p.Logf("Supervisor is shutting down: releasing lock...")
					err = d.DestroySession()
					if err != nil {
						p.Logf("failed to release lock %v", err)
					}
					p.Logf("Stopping Consul Connect watchers...")
					caRootWatcher.Stop()
					leafWatcher.Stop()
					eventsWatcher.Stop()
					return nil // we are done in the Worker: get out...
				}
			}
		},
		Retry: true,
	}

	return worker, nil
}

func (w *consulwatchman) Work(p *supervisor.Process) error {
	p.Ready()
	for {
		select {
		case watches := <-w.watchesCh:
			found := make(map[string]*supervisor.Worker)
			p.Logf("processing %d consul watches", len(watches))
			for _, cw := range watches {
				worker, err := w.WatchMaker.MakeConsulWatch(cw)
				if err != nil {
					p.Logf("failed to create consul watch %v", err)
					continue
				}

				if _, exists := w.watched[worker.Name]; exists {
					found[worker.Name] = w.watched[worker.Name]
				} else {
					p.Logf("add consul watcher %s\n", worker.Name)
					p.Supervisor().Supervise(worker)
					w.watched[worker.Name] = worker
					found[worker.Name] = worker
				}
			}

			// purge the watches that no longer are needed because they did not come through the in the latest
			// report
			for workerName, worker := range w.watched {
				if _, exists := found[workerName]; !exists {
					p.Logf("remove consul watcher %s\n", workerName)
					worker.Shutdown()
					worker.Wait()
				}
			}

			w.watched = found
		case <-p.Shutdown():
			p.Logf("shutdown initiated")
			return nil
		}
	}
}

func createCertificateChain(rootPEM string, leafPEM string) string {
	return leafPEM + rootPEM
}

func formatKubernetesSecretYAML(name string, chain string, key string) string {
	chain64 := base64.StdEncoding.EncodeToString([]byte(chain))
	key64 := base64.StdEncoding.EncodeToString([]byte(key))

	return fmt.Sprintf(secretTemplate, name, chain64, key64)
}

func applySecret(namespace string, yaml string) error {
	// TODO(alvaro): replace by a proper k8s API call
	args := []string{"apply", "-f", "-"}

	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}

	cmd := exec.Command("kubectl", args...)

	var errBuffer bytes.Buffer
	cmd.Stderr = &errBuffer

	cmd.Stdin = bytes.NewBuffer([]byte(yaml))

	_, err := cmd.Output()
	fmt.Println(errBuffer.String())

	return err
}
