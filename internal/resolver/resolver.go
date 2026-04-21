// Package resolver provides async reverse-DNS lookup and port-to-service-name mapping.
package resolver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	negativeTTL    = 2 * time.Minute // retry failed lookups after this
	maxConcurrent  = 32              // cap on simultaneous DNS goroutines
)

type entry struct {
	name string    // resolved hostname; empty means lookup failed
	at   time.Time // when this entry was stored
	fail bool      // true = lookup failed
}

// Resolver performs async reverse-DNS lookups and caches results.
// The zero value is not usable; call New().
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]entry
	inflight map[string]struct{}
	sem      chan struct{} // bounds concurrent goroutines
}

func New() *Resolver {
	return &Resolver{
		cache:    make(map[string]entry),
		inflight: make(map[string]struct{}),
		sem:      make(chan struct{}, maxConcurrent),
	}
}

// Hostname returns the best available name for ip.
// If a cached result exists it is returned immediately.
// Otherwise ip.String() is returned and an async lookup is started.
// The caller will get the real hostname on the next call after resolution completes.
func (r *Resolver) Hostname(ip net.IP) string {
	if ip == nil {
		return ""
	}
	key := ip.String()

	r.mu.RLock()
	e, ok := r.cache[key]
	r.mu.RUnlock()

	if ok {
		if !e.fail {
			return e.name
		}
		if time.Since(e.at) < negativeTTL {
			return key // within negative TTL, don't retry yet
		}
		// expired negative entry — fall through and retry
	}

	// Kick off an async lookup if none is already running.
	r.mu.Lock()
	if _, pending := r.inflight[key]; !pending {
		r.inflight[key] = struct{}{}
		go r.resolve(key)
	}
	r.mu.Unlock()

	return key
}

func (r *Resolver) resolve(ipStr string) {
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	names, err := net.LookupAddr(ipStr)

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, ipStr)

	if err != nil || len(names) == 0 {
		r.cache[ipStr] = entry{fail: true, at: time.Now()}
		return
	}
	// net.LookupAddr returns FQDNs with a trailing dot — strip it.
	r.cache[ipStr] = entry{name: strings.TrimSuffix(names[0], "."), at: time.Now()}
}

// ServiceName returns a human-readable label for port, e.g. 443 → "https".
// Falls back to the numeric string for unknown ports.
func ServiceName(port uint16) string {
	if name, ok := knownPorts[port]; ok {
		return name
	}
	return fmt.Sprintf("%d", port)
}

// knownPorts covers the ports seen most often in practice.
// Kept deliberately short; /etc/services has thousands of entries most users never see.
var knownPorts = map[uint16]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	67:    "dhcp",
	68:    "dhcp",
	80:    "http",
	110:   "pop3",
	123:   "ntp",
	143:   "imap",
	179:   "bgp",
	389:   "ldap",
	443:   "https",
	465:   "smtps",
	514:   "syslog",
	587:   "smtp-sub",
	636:   "ldaps",
	853:   "dns-tls",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "mssql",
	1521:  "oracle",
	1883:  "mqtt",
	2375:  "docker",
	2376:  "docker-tls",
	3306:  "mysql",
	3389:  "rdp",
	4222:  "nats",
	5432:  "postgres",
	5672:  "amqp",
	5900:  "vnc",
	6379:  "redis",
	6443:  "k8s-api",
	8080:  "http-alt",
	8443:  "https-alt",
	8888:  "jupyter",
	9090:  "prometheus",
	9092:  "kafka",
	9200:  "elastic",
	9300:  "elastic-p",
	11211: "memcached",
	15672: "rabbitmq",
	27017: "mongodb",
}
