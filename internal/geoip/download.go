package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxmindURL = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"

// Download fetches both GeoLite2-Country and GeoLite2-ASN databases using the
// provided MaxMind license key and saves the MMDB files to DataDir.
// progress is called with each status line (suitable for fmt.Println).
func Download(licenseKey string, progress func(string)) error {
	dir := DataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", dir, err)
	}

	editions := []struct {
		id   string
		file string
	}{
		{"GeoLite2-Country", countryDBName},
		{"GeoLite2-ASN", asnDBName},
	}

	for _, e := range editions {
		progress(fmt.Sprintf("Downloading %s…", e.id))
		url := fmt.Sprintf(maxmindURL, e.id, licenseKey)
		dest := filepath.Join(dir, e.file)
		if err := fetchMMDB(url, dest); err != nil {
			return fmt.Errorf("%s: %w", e.id, err)
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

// fetchMMDB downloads a MaxMind tar.gz archive and extracts the first .mmdb
// file found inside it to dest.
func fetchMMDB(url, dest string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d — verify your license key at maxmind.com", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		f, err := os.Create(dest)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, tr)
		f.Close()
		return err
	}
	return fmt.Errorf(".mmdb not found inside archive")
}
