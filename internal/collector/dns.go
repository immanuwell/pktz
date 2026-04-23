package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

const (
	maxDNSHistory    = 200
	dnsPendingExpiry = 5 * time.Second
)

// DNSRecord is one completed DNS transaction (query + matched response).
type DNSRecord struct {
	Time     time.Time
	Resolver net.IP
	Name     string        // query domain name
	QType    string        // "A", "AAAA", "MX", etc.
	RTT      time.Duration // 0 if response not yet matched
	Status   string        // "NOERROR", "NXDOMAIN", "SERVFAIL", "TIMEOUT", etc.
	Answers  []string      // IP strings or CNAME targets
}

// dnsKey uniquely identifies an in-flight DNS transaction.
type dnsKey struct {
	pid  uint32
	txID uint16
}

// pendingDNS is a DNS query waiting to be matched with its response.
type pendingDNS struct {
	sentAt   time.Time
	name     string
	qtype    string
	resolver net.IP
}

// dnsRawEvent mirrors struct dns_event in bpf/pktz.c.
// Field order and types are chosen so binary.Read (little-endian) matches
// the C layout with no padding: 8+4+2+1+1+16+256+16 = 304 bytes.
type dnsRawEvent struct {
	TsNs       uint64
	Pid        uint32
	PayloadLen uint16
	IsTx       uint8
	Family     uint8
	Raddr      [16]byte
	Payload    [256]byte
	Comm       [16]byte
}

// runDNS reads dns_events from the eBPF ringbuf in a dedicated goroutine.
// Call once from Run(); it exits when dnsRdr is closed.
func (c *Collector) runDNS() {
	for {
		rec, err := c.dnsRdr.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(rec.RawSample) < 304 {
			continue
		}
		var ev dnsRawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		c.processDNSEvent(&ev)
	}
}

func (c *Collector) processDNSEvent(ev *dnsRawEvent) {
	if ev.Pid == 0 || ev.PayloadLen < 12 {
		return
	}
	payload := ev.Payload[:ev.PayloadLen]
	txID, isResp, rcode, name, qtype, answers := parseDNS(payload)
	if name == "" && !isResp {
		return
	}

	resolver := rawAddrToIP(ev.Raddr, ev.Family)
	ts := time.Unix(0, int64(ev.TsNs))
	key := dnsKey{pid: ev.Pid, txID: txID}

	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()

	if !isResp {
		// Outgoing query: store as pending.
		c.dnsPending[key] = pendingDNS{
			sentAt:   ts,
			name:     name,
			qtype:    qtype,
			resolver: resolver,
		}
		return
	}

	// Incoming response: match with pending query.
	pq, ok := c.dnsPending[key]
	if !ok {
		// No pending query — capture as standalone record with unknown query name.
		pq = pendingDNS{
			sentAt:   ts,
			name:     name,
			qtype:    qtype,
			resolver: resolver,
		}
	} else {
		delete(c.dnsPending, key)
	}

	if pq.name == "" {
		pq.name = name
	}
	if pq.resolver == nil {
		pq.resolver = resolver
	}

	rtt := ts.Sub(pq.sentAt)
	if rtt < 0 {
		rtt = 0
	}

	rec := DNSRecord{
		Time:     pq.sentAt,
		Resolver: pq.resolver,
		Name:     pq.name,
		QType:    pq.qtype,
		RTT:      rtt,
		Status:   rcodeString(rcode),
		Answers:  answers,
	}

	pid := ev.Pid
	h := c.dnsHistory[pid]
	h = append(h, rec)
	if len(h) > maxDNSHistory {
		h = h[len(h)-maxDNSHistory:]
	}
	c.dnsHistory[pid] = h

	// Update IP→name reverse map for connection enrichment.
	nm := c.dnsNames[pid]
	if nm == nil {
		nm = make(map[string]string)
		c.dnsNames[pid] = nm
	}
	for _, ans := range answers {
		if !strings.HasPrefix(ans, "CNAME:") {
			nm[ans] = pq.name
		}
	}
}

// expirePendingDNS removes queries older than dnsPendingExpiry.
// Called periodically from poll() to prevent unbounded map growth.
func (c *Collector) expirePendingDNS(now time.Time) {
	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()
	for k, pq := range c.dnsPending {
		if now.Sub(pq.sentAt) > dnsPendingExpiry {
			delete(c.dnsPending, k)
		}
	}
}

// DNSHistory returns up to maxDNSHistory DNS records for pid, oldest first.
func (c *Collector) DNSHistory(pid uint32) []DNSRecord {
	c.dnsMu.RLock()
	defer c.dnsMu.RUnlock()
	src := c.dnsHistory[pid]
	if len(src) == 0 {
		return nil
	}
	out := make([]DNSRecord, len(src))
	copy(out, src)
	return out
}

// DNSNames returns the IP→domain-name map observed for pid (for connection enrichment).
func (c *Collector) DNSNames(pid uint32) map[string]string {
	c.dnsMu.RLock()
	defer c.dnsMu.RUnlock()
	src := c.dnsNames[pid]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// rawAddrToIP converts the raddr field of dnsRawEvent to a net.IP.
// For AF_INET, only the first 4 bytes are used (network byte order).
func rawAddrToIP(raddr [16]byte, family uint8) net.IP {
	if family == 2 { // AF_INET
		return net.IP{raddr[0], raddr[1], raddr[2], raddr[3]}
	}
	ip := make(net.IP, 16)
	copy(ip, raddr[:])
	return ip
}

// ── DNS wire-format parser ────────────────────────────────────────────────────

// parseDNS parses a raw DNS message and returns:
//
//	txID, isResponse, rcode, queryName, qtype, answers
func parseDNS(b []byte) (txID uint16, isResp bool, rcode uint8, name, qtype string, answers []string) {
	if len(b) < 12 {
		return
	}
	txID = uint16(b[0])<<8 | uint16(b[1])
	flags := uint16(b[2])<<8 | uint16(b[3])
	isResp = flags&0x8000 != 0
	rcode = uint8(flags & 0x000F)
	qdcount := int(uint16(b[4])<<8 | uint16(b[5]))
	ancount := int(uint16(b[6])<<8 | uint16(b[7]))

	pos := 12
	if qdcount > 0 {
		var nextPos int
		name, nextPos = parseDNSName(b, pos)
		pos = nextPos
		if pos+4 <= len(b) {
			qtypeNum := uint16(b[pos])<<8 | uint16(b[pos+1])
			qtype = dnsTypeName(qtypeNum)
			pos += 4 // QTYPE(2) + QCLASS(2)
		}
	}

	if isResp && ancount > 0 {
		for i := 0; i < ancount && pos < len(b); i++ {
			_, pos = parseDNSName(b, pos) // owner name
			if pos+10 > len(b) {
				break
			}
			atype := uint16(b[pos])<<8 | uint16(b[pos+1])
			rdlen := int(uint16(b[pos+8])<<8 | uint16(b[pos+9]))
			pos += 10
			if pos+rdlen > len(b) {
				break
			}
			switch atype {
			case 1: // A
				if rdlen == 4 {
					answers = append(answers, net.IP(b[pos:pos+4]).String())
				}
			case 28: // AAAA
				if rdlen == 16 {
					answers = append(answers, net.IP(b[pos:pos+16]).String())
				}
			case 5: // CNAME
				cname, _ := parseDNSName(b, pos)
				answers = append(answers, "CNAME:"+cname)
			}
			pos += rdlen
		}
	}
	return
}

// parseDNSName decodes a DNS name at position pos in b, following compression
// pointers. Returns the decoded name and the position after the name in the
// original message (not after any pointer target).
func parseDNSName(b []byte, pos int) (string, int) {
	var labels []string
	nextPos := -1
	seen := make(map[int]bool)

	for pos < len(b) {
		if seen[pos] {
			break
		}
		seen[pos] = true
		byt := b[pos]
		if byt == 0 {
			pos++
			break
		}
		if byt&0xC0 == 0xC0 {
			// Compression pointer.
			if pos+1 >= len(b) {
				pos += 2
				break
			}
			if nextPos < 0 {
				nextPos = pos + 2
			}
			ptr := (int(byt&0x3F) << 8) | int(b[pos+1])
			pos = ptr
			continue
		}
		length := int(byt)
		pos++
		if pos+length > len(b) {
			break
		}
		labels = append(labels, string(b[pos:pos+length]))
		pos += length
	}
	if nextPos < 0 {
		nextPos = pos
	}
	return strings.Join(labels, "."), nextPos
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func rcodeString(rcode uint8) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}
