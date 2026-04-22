package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// containerIDRe matches a 64-character lowercase hex OCI container ID.
// These appear in cgroup paths produced by Docker, containerd, and Podman.
var containerIDRe = regexp.MustCompile(`[a-f0-9]{64}`)

// readContainerID returns the 64-char OCI container ID for pid by reading
// /proc/<pid>/cgroup, or "" if the process is not inside a container.
func readContainerID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	m := containerIDRe.Find(data)
	if m == nil {
		return ""
	}
	return string(m)
}

var dockerHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
	},
	Timeout: 2 * time.Second,
}

// lookupDockerName queries the Docker socket for the human-readable name of
// containerID. Returns "" when Docker is unavailable or the container is unknown.
func lookupDockerName(containerID string) string {
	resp, err := dockerHTTPClient.Get("http://localhost/containers/" + containerID + "/json")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var info struct {
		Name string `json:"Name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ""
	}
	return strings.TrimPrefix(info.Name, "/")
}
