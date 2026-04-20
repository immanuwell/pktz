package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tcpStates maps /proc/net/tcp state hex codes to human-readable names.
var tcpStates = map[uint8]string{
	0x01: "ESTABLISHED", 0x02: "SYN_SENT", 0x03: "SYN_RECV",
	0x04: "FIN_WAIT1", 0x05: "FIN_WAIT2", 0x06: "TIME_WAIT",
	0x07: "CLOSE", 0x08: "CLOSE_WAIT", 0x09: "LAST_ACK",
	0x0A: "LISTEN", 0x0B: "CLOSING",
}

type rawSocket struct {
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16
	state      uint8
	inode      uint64
	proto      string
}

// ScanNetConnections reads /proc/net/tcp and /proc/net/udp, correlates socket
// inodes with /proc/PID/fd, and returns one ProcConn per network socket.
func ScanNetConnections() []ProcConn {
	sockets := collectSockets()
	if len(sockets) == 0 {
		return nil
	}

	inodePID := buildInodePIDMap()

	out := make([]ProcConn, 0, len(sockets))
	for _, s := range sockets {
		if s.inode == 0 {
			continue
		}
		pid, ok := inodePID[s.inode]
		if !ok {
			continue
		}
		stateName := "UNKNOWN"
		if s.proto == "UDP" {
			stateName = ""
		} else if n, ok := tcpStates[s.state]; ok {
			stateName = n
		}
		out = append(out, ProcConn{
			PID:        pid,
			SrcAddr:    s.localIP,
			SrcPort:    s.localPort,
			DstAddr:    s.remoteIP,
			DstPort:    s.remotePort,
			Proto:      s.proto,
			State:      stateName,
		})
	}
	return out
}

// ProcConn is a raw connection entry from /proc/net before eBPF rates are applied.
type ProcConn struct {
	PID        uint32
	SrcAddr    net.IP
	SrcPort    uint16
	DstAddr    net.IP
	DstPort    uint16
	Proto      string
	State      string
}

func collectSockets() []rawSocket {
	files := []struct{ path, proto string }{
		{"/proc/net/tcp", "TCP"},
		{"/proc/net/udp", "UDP"},
	}
	var out []rawSocket
	for _, f := range files {
		ss, err := parseProcNetFile(f.path, f.proto)
		if err == nil {
			out = append(out, ss...)
		}
	}
	return out
}

func parseProcNetFile(path, proto string) ([]rawSocket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []rawSocket
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		localIP, localPort, err := parseHexAddrV4(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, _ := parseHexAddrV4(fields[2])

		stateVal, _ := strconv.ParseUint(fields[3], 16, 8)
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		out = append(out, rawSocket{
			localIP:    localIP,
			localPort:  localPort,
			remoteIP:   remoteIP,
			remotePort: remotePort,
			state:      uint8(stateVal),
			inode:      inode,
			proto:      proto,
		})
	}
	return out, sc.Err()
}

// parseHexAddrV4 decodes an "AABBCCDD:PPPP" entry from /proc/net/tcp.
// The 4-byte address is stored in little-endian (native x86) order.
func parseHexAddrV4(s string) (net.IP, uint16, error) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return nil, 0, fmt.Errorf("bad addr: %s", s)
	}
	addrHex, portHex := s[:idx], s[idx+1:]

	if len(addrHex) != 8 {
		return nil, 0, fmt.Errorf("not ipv4: %s", addrHex)
	}
	b, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0, err
	}
	// Little-endian on-disk → reverse to get dotted-decimal order
	ip := net.IP{b[3], b[2], b[1], b[0]}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	return ip, uint16(port), nil
}

// buildInodePIDMap walks /proc/PID/fd to map socket inodes to their owning PID.
func buildInodePIDMap() map[uint64]uint32 {
	result := make(map[uint64]uint32, 512)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // skip non-numeric entries like "net", "self"
		}

		fdGlob := fmt.Sprintf("/proc/%d/fd/*", pid)
		fds, _ := filepath.Glob(fdGlob)
		for _, fdPath := range fds {
			target, err := os.Readlink(fdPath)
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inodeStr := target[8 : len(target)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			result[inode] = uint32(pid)
		}
	}
	return result
}
