package geoip

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DB-IP.com publishes free MMDB databases monthly at a predictable URL.
// No registration or license key required (CC BY 4.0).
const dbipURL = "https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz"

// Download fetches both DB-IP Country Lite and ASN Lite databases and saves
// the MMDB files to DataDir. progress is called with each status line.
func Download(progress func(string)) error {
	dir := DataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", dir, err)
	}

	yearMonth := time.Now().Format("2006-01")

	editions := []struct {
		slug string
		file string
	}{
		{"country", countryDBName},
		{"asn", asnDBName},
	}

	for _, e := range editions {
		url := fmt.Sprintf(dbipURL, e.slug, yearMonth)
		dest := filepath.Join(dir, e.file)
		progress(fmt.Sprintf("Downloading db-ip %s lite (%s)…", e.slug, yearMonth))
		if err := fetchMMDB(url, dest); err != nil {
			return fmt.Errorf("%s: %w", e.slug, err)
		}
		fi, _ := os.Stat(dest)
		size := ""
		if fi != nil {
			size = fmt.Sprintf(" (%.1f MB)", float64(fi.Size())/1e6)
		}
		progress(fmt.Sprintf("  saved → %s%s", dest, size))
	}
	return nil
}

// fetchMMDB downloads a gzip-compressed MMDB file and decompresses it to dest.
func fetchMMDB(url, dest string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, gz)
	f.Close()
	if err != nil {
		os.Remove(dest)
	}
	return err
}
