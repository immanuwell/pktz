<p align="center">packet-z</p>

![](media/screenshot-1.png)

![](media/screenshot-2.png)

![](media/screenshot-3.png)

# pktz

Your machine is talking to things right now. A lot of things. `pktz` tells you exactly who, how much, and to where — in real time.

Built on eBPF, so it hooks straight into the kernel. No polling `/proc`. No sampling. Every byte, every process, no excuses.

---

## Install

**Download a pre-built binary** (no Go required):

```bash
# replace with your arch: amd64, arm64, armv7
curl -Lo pktz https://github.com/immanuwell/pktz/releases/latest/download/pktz-linux-amd64
chmod +x pktz && sudo mv pktz /usr/local/bin/
```

**Or with Go** (fetches + compiles in one shot):

```bash
go install github.com/immanuwell/pktz@latest
```

The eBPF objects are pre-compiled and bundled in the module, so no `clang` or `bpftool` needed.

**Or build from source** (if you want to hack on it):

```bash
# requires: clang, libbpf-dev, bpftool, Go 1.22+, Linux kernel 5.8+
make install   # builds + copies to /usr/local/bin
```

## Usage

```bash
sudo pktz
```

Needs root to load eBPF programs and read `/proc/<pid>/fd/` for all processes — same deal as `sudo iotop`, `sudo tcpdump`, etc.

If you really hate typing sudo, you can grant capabilities once:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search+ep $(which pktz)
pktz  # no sudo needed
```

Fair warning though: in this mode pktz will see fewer processes than with sudo — it won't be able to inspect fd dirs of processes owned by root or other users, so their connections won't show up in the detail view. For full visibility, sudo is the way.

---

## What you actually get

**Process list** — every process doing network I/O, with live RX/TX rates and totals. Sorted by name by default, but you can sort by anything.

**Connection drill-down** — hit `Enter` on any process. See every single open connection, its state, rates, remote address. Hit `Esc` to go back.

**Live graph** — 5-minute RX/TX history chart, auto-follows whatever process your cursor is on. Rendered in Unicode block chars, looks goated in a dark terminal.

**GeoIP flags + ASN** — 🇺🇸 CLOUDFLARE, 🇩🇪 HETZNER, 🇷🇺 ???. Optional, see below.

**DNS resolution** — remote addresses show real hostnames instead of raw IPs. You can toggle it off if you want the raw view.

---

## Keybindings

| Key | Action |
|-----|--------|
| `↑` `↓` or `j` `k` | navigate |
| `Enter` | open connection detail |
| `Esc` / `Backspace` | back to process list |
| `s` | cycle sort column |
| `/` | filter processes by name |
| `r` | toggle hostname resolution |
| `v` | toggle compact IPv6 |
| `g` | toggle GeoIP flags |
| `m` | toggle mouse |
| `q` | quit |

Click column headers to sort. Click again to flip direction. Yes, mouse works out of the box.

---

## GeoIP (optional but lowkey essential)

```bash
sudo pktz --download-geoip-db
```

Downloads from DB-IP.com. No account, no license key, nothing. CC BY 4.0. Once downloaded, press `g` to toggle country flags and ASN names in the connection detail view.

Incredibly useful when you're staring at some IP and wondering why your laptop is making friends in unexpected places.

---

## Focus on a specific process

Skip the process list and jump straight to what you care about:

```bash
# by PID — opens connection detail view directly
sudo pktz --pid 1234

# by name — filters the list to matching processes
sudo pktz --app firefox
sudo pktz --app /usr/bin/google-chrome   # path works too, basename is extracted
```

`--app` does a case-insensitive substring match against the process name, so `--app chrom` catches both `chrome` and `chromium`. The footer shows `app:firefox` as a reminder that a filter is active. You can still use `/` on top of it to narrow down further.

Both flags work with `--log` and `--metrics` too.

---

## Log mode — pipe it anywhere

```bash
sudo pktz --log | jq .
```

Skips the TUI entirely and emits NDJSON to stdout every 500ms. Every line is either a `"process"` record or a `"conn"` record, both with a `ts` timestamp.

```bash
# top bandwidth hogs right now
sudo pktz --log | jq -r 'select(.type=="process") | "\(.comm) rx=\(.rx_bps|./1024|floor)KB/s"'

# watch a specific process
sudo pktz --log | grep '"comm":"firefox"'

# alert when something crosses a threshold
sudo pktz --log | jq --unbuffered 'select(.type=="process" and .rx_bps > 10000000)' | notify
```

Plays well with anything that reads stdin. Set and forget.

---

## Prometheus metrics endpoint

```bash
sudo pktz --metrics :9090
```

Starts an HTTP server at `/metrics` alongside the TUI. Prometheus can scrape it immediately. Exposes per-process gauges and counters:

| Metric | Type | Description |
|--------|------|-------------|
| `pktz_process_rx_bytes_per_second` | gauge | Current RX rate |
| `pktz_process_tx_bytes_per_second` | gauge | Current TX rate |
| `pktz_process_rx_bytes_total` | counter | Total bytes received |
| `pktz_process_tx_bytes_total` | counter | Total bytes transmitted |
| `pktz_process_connections` | gauge | Open connection count |

All metrics are labeled with `pid` and `comm` (process name).

Works with any combination of flags. Headless/daemon use case:

```bash
# no TUI, just metrics — pipe log to /dev/null
sudo pktz --metrics :9090 --log > /dev/null

# only expose metrics for one app
sudo pktz --metrics :9090 --app firefox
```

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: pktz
    static_configs:
      - targets: ['localhost:9090']
```

---

## Demo mode — safe for screen sharing

Presenting to an audience and don't want your actual IPs on screen?

```bash
sudo pktz --demo
```

Every IP and hostname gets replaced with a convincing-looking but totally fake one. Stable within the session — same real IP always maps to the same fake — so the display still makes sense.

Want to make it really pop for a talk or a screenshot:

```bash
sudo pktz --fake-processes=chrome,spotify,zoom
```

Injects synthetic processes with animated traffic curves. Implies `--demo`. Looks completely real, is completely fake. ngl it's kind of fun to watch.

---

That's it. Run it, spend 30 seconds poking around, you'll figure out the rest.
