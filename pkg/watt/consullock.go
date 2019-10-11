package watt

import (
	"encoding/json"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
)

const (
	// DefaultLockRetryInterval is how long we wait after a failed lock acquisition
	DefaultLockRetryInterval = 30 * time.Second
	// DefautSessionTTL is ttl for the session created
	DefautSessionTTL = 5 * time.Minute
)

// DistLock configured for lock acquisition
type DistLock struct {
	ConsulClient      *consulapi.Client
	Key               string
	SessionID         string
	LockRetryInterval time.Duration
	SessionTTL        time.Duration
	PermanentRelease  bool
}

// New returns a new DistLock object
func NewDistLock(consulClient *consulapi.Client, key string, interval time.Duration) (*DistLock, error) {
	var d DistLock

	d.ConsulClient = consulClient
	d.Key = key
	d.LockRetryInterval = DefaultLockRetryInterval
	d.SessionTTL = DefautSessionTTL

	if interval != 0 {
		d.LockRetryInterval = interval
	}

	return &d, nil
}

// RetryLockAcquire attempts to acquire the lock at `LockRetryInterval`
// First consul session is created and then attempt is done to acquire lock on this session
// Checks configured over Session is all the checks configured for the client itself
// sends msg to chan `acquired` once lock is acquired
// msg is sent to `released` chan when the lock is released due to consul session invalidation
func (d *DistLock) RetryLockAcquire(acquired chan<- bool, released chan<- bool) {
	if d.PermanentRelease {
		log.Printf("lock is permanently released. last session id - %+s", d.SessionID)
		return
	}
	ticker := time.NewTicker(d.LockRetryInterval)
	for ; true; <-ticker.C {
		value := map[string]string{
			"key":                 d.Key,
			"lockAcquisitionTime": time.Now().Format(time.RFC3339),
		}
		lock, err := d.acquireLock(value, released)
		if err != nil {
			log.Println("error on acquireLock :", err, "retry in -", d.LockRetryInterval)
			continue
		}
		if lock {
			log.Printf("lock acquired with consul session - %s", d.SessionID)
			ticker.Stop()
			acquired <- true
			break
		}
	}
}

// DestroySession invalidates the consul session and indirectly release the acquired lock if any
// Should be called in destructor function e.g clean-up, service reload
// this will give others a chance to acquire lock
func (d *DistLock) DestroySession() error {
	if d.SessionID == "" {
		log.Printf("cannot destroy empty session")
		return nil
	}
	_, err := d.ConsulClient.Session().Destroy(d.SessionID, nil)
	if err != nil {
		return err
	}
	log.Printf("destroyed consul session - %s", d.SessionID)
	d.PermanentRelease = true
	return nil
}

func (d *DistLock) createSession() (string, error) {
	return createSession(d.ConsulClient, d.Key, d.SessionTTL)
}

func (d *DistLock) recreateSession() error {
	sessionID, err := d.createSession()
	if err != nil {
		return err
	}
	d.SessionID = sessionID
	return nil
}

func (d *DistLock) acquireLock(value map[string]string, released chan<- bool) (bool, error) {
	if d.SessionID == "" {
		err := d.recreateSession()
		if err != nil {
			return false, err
		}
	}
	b, err := json.Marshal(value)
	if err != nil {
		log.Println("error on value marshal", err)
	}
	lockOpts := &consulapi.LockOptions{
		Key:          d.Key,
		Value:        b,
		Session:      d.SessionID,
		LockWaitTime: 1 * time.Second,
		LockTryOnce:  true,
	}
	lock, err := d.ConsulClient.LockOpts(lockOpts)
	if err != nil {
		return false, err
	}
	a, _, err := d.ConsulClient.Session().Info(d.SessionID, nil)
	if err == nil && a == nil {
		log.Printf("consul session - %s is invalid now", d.SessionID)
		d.SessionID = ""
		return false, nil
	}
	if err != nil {
		return false, err
	}

	resp, err := lock.Lock(nil)
	if err != nil {
		return false, err
	}
	if resp != nil {
		doneCh := make(chan struct{})
		go func() { d.ConsulClient.Session().RenewPeriodic(d.SessionTTL.String(), d.SessionID, nil, doneCh) }()
		go func() {
			<-resp
			log.Printf("lock released with session - %s", d.SessionID)
			close(doneCh)
			released <- true
		}()
		return true, nil
	}

	return false, nil
}

func createSession(client *consulapi.Client, consulKey string, ttl time.Duration) (string, error) {
	agentChecks, err := client.Agent().Checks()
	if err != nil {
		log.Println("error on getting checks", err)
		return "", err
	}
	checks := []string{}
	checks = append(checks, "serfHealth")
	for _, j := range agentChecks {
		checks = append(checks, j.CheckID)
	}

	sessionID, _, err := client.Session().Create(&consulapi.SessionEntry{Name: consulKey, Checks: checks, LockDelay: 0 * time.Second, TTL: ttl.String()}, nil)
	if err != nil {
		return "", err
	}
	log.Println("created consul session -", sessionID)
	return sessionID, nil
}
