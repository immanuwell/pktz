// Package geoip provides country flag and ASN org lookup from MaxMind GeoLite2
// MMDB files stored in the user's data directory.
package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

const (
	countryDBName = "GeoLite2-Country.mmdb"
	asnDBName     = "GeoLite2-ASN.mmdb"
)

// DataDir returns the directory where the MMDB files are stored.
// Respects XDG_DATA_HOME; falls back to ~/.local/share/pktz.
func DataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "pktz")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "pktz")
}

// DBPaths returns the expected on-disk paths for the two MMDB files.
func DBPaths() (country, asn string) {
	d := DataDir()
	return filepath.Join(d, countryDBName), filepath.Join(d, asnDBName)
}

// DBExists reports whether both MMDB files are present on disk.
func DBExists() bool {
	c, a := DBPaths()
	_, errC := os.Stat(c)
	_, errA := os.Stat(a)
	return errC == nil && errA == nil
}

// Info is the geo annotation for one IP address.
type Info struct {
	Flag string // emoji flag, e.g. "🇺🇸"
	Org  string // shortened ASN org name, e.g. "GOOGLE"
}

func (i Info) IsZero() bool { return i.Flag == "" && i.Org == "" }

// DB holds open MMDB readers and a lookup cache.
type DB struct {
	country *geoip2.Reader
	asn     *geoip2.Reader

	mu    sync.RWMutex
	cache map[string]Info
}

// Open opens both MMDB files from DataDir.
func Open() (*DB, error) {
	cPath, aPath := DBPaths()
	country, err := geoip2.Open(cPath)
	if err != nil {
		return nil, err
	}
	asn, err := geoip2.Open(aPath)
	if err != nil {
		country.Close()
		return nil, err
	}
	return &DB{
		country: country,
		asn:     asn,
		cache:   make(map[string]Info, 256),
	}, nil
}

// Close releases the MMDB file handles.
func (db *DB) Close() {
	db.country.Close()
	db.asn.Close()
}

// Lookup returns the GeoIP annotation for ip.
// Loopback, private, link-local, and unspecified addresses return a zero Info.
func (db *DB) Lookup(ip net.IP) Info {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return Info{}
	}

	key := ip.String()

	db.mu.RLock()
	if v, ok := db.cache[key]; ok {
		db.mu.RUnlock()
		return v
	}
	db.mu.RUnlock()

	info := db.doLookup(ip)

	db.mu.Lock()
	db.cache[key] = info
	db.mu.Unlock()

	return info
}

func (db *DB) doLookup(ip net.IP) Info {
	var flag, org string

	if rec, err := db.country.Country(ip); err == nil {
		code := rec.Country.IsoCode
		if code == "" {
			code = rec.RegisteredCountry.IsoCode
		}
		flag = countryFlag(code)
	}

	if rec, err := db.asn.ASN(ip); err == nil {
		org = shortOrg(rec.AutonomousSystemOrganization)
	}

	return Info{Flag: flag, Org: org}
}

// countryFlag converts an ISO 3166-1 alpha-2 code to a Unicode flag emoji.
func countryFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	r1 := rune(0x1F1E6) + rune(code[0]-'A')
	r2 := rune(0x1F1E6) + rune(code[1]-'A')
	return string([]rune{r1, r2})
}

// shortOrg strips legal suffixes and truncates long org names.
func shortOrg(name string) string {
	if name == "" {
		return ""
	}
	upper := strings.ToUpper(name)
	for _, suffix := range []string{
		", INC.", " INC.", " LLC", " LTD.", " GMBH", " B.V.",
		" AG", " CORP.", " S.A.", " S.R.L.", " PLC",
	} {
		if i := strings.Index(upper, suffix); i > 0 {
			name = name[:i]
			break
		}
	}
	name = strings.TrimSpace(strings.ToUpper(name))
	const maxLen = 14
	if len([]rune(name)) > maxLen {
		runes := []rune(name)
		name = string(runes[:maxLen-1]) + "…"
	}
	return name
}
