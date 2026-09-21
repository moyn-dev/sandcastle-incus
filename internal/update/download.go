package update

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// binaryName is the single file inside every release tarball.
const binaryName = "sandcastle"

// checksumsAsset is GoReleaser's unified SHA-256 manifest asset.
const checksumsAsset = "checksums.txt"

// maxBinarySize caps download/extract sizes as a sanity bound (the real
// tarballs are ~10MB).
const maxBinarySize = 512 << 20

// AssetName returns the release tarball name for a platform, matching the
// GoReleaser name_template sandcastle-{{ .Os }}-{{ .Arch }}.
func AssetName(goos, goarch string) string {
	return fmt.Sprintf("sandcastle-%s-%s.tar.gz", goos, goarch)
}

// ParseChecksums parses sha256sum-format output (checksums.txt) into a
// map of file name → lowercase hex digest. Malformed lines are skipped.
func ParseChecksums(data []byte) map[string]string {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		sums[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return sums
}

// FetchBinary downloads the platform tarball for the release, verifies its
// SHA-256 against the release's checksums.txt, and returns the extracted
// sandcastle binary.
func (c *Checker) FetchBinary(ctx context.Context, rel Release, goos, goarch string) ([]byte, error) {
	asset := AssetName(goos, goarch)
	assetURL, ok := rel.AssetURL(asset)
	if !ok {
		return nil, fmt.Errorf("release %s has no asset %s", rel.TagName, asset)
	}
	sumsURL, ok := rel.AssetURL(checksumsAsset)
	if !ok {
		return nil, fmt.Errorf("release %s has no %s", rel.TagName, checksumsAsset)
	}

	sumsData, err := c.download(ctx, sumsURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", checksumsAsset, err)
	}
	want, ok := ParseChecksums(sumsData)[asset]
	if !ok {
		return nil, fmt.Errorf("%s has no entry for %s", checksumsAsset, asset)
	}

	archive, err := c.download(ctx, assetURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", asset, err)
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("checksum mismatch for %s: got %x, want %s", asset, got, want)
	}
	return extractBinary(archive)
}

// downloadTimeout bounds one asset download. The API client's 30 s is far too
// short for a ~40 MB tarball on a slow link (seen live: "context deadline
// exceeded while reading body"); ctx still cancels earlier if the caller does.
const downloadTimeout = 15 * time.Minute

// downloadRetries / downloadRetryDelay cover GitHub's release CDN answering
// 5xx (seen: 504 for minutes) for assets a release just published, while
// the same asset is already listed as uploaded. Retry a few times before
// giving up; a 4xx is final.
const (
	downloadRetries    = 6
	downloadRetryDelay = 10 * time.Second
)

func (c *Checker) download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	client := *c.client()
	client.Timeout = 0 // the context above is the deadline
	var lastErr error
	for attempt := 0; attempt <= downloadRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, lastErr
			case <-time.After(c.retryDelay()):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status %s (a release's assets can lag on GitHub's download CDN for a few minutes)", resp.Status)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %s", resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxBinarySize))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

// retryDelay is downloadRetryDelay unless a test shortens it.
func (c *Checker) retryDelay() time.Duration {
	if c.RetryDelay > 0 {
		return c.RetryDelay
	}
	return downloadRetryDelay
}

func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open tarball: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("tarball has no %s binary", binaryName)
		}
		if err != nil {
			return nil, fmt.Errorf("read tarball: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && strings.TrimPrefix(hdr.Name, "./") == binaryName {
			return io.ReadAll(io.LimitReader(tr, maxBinarySize))
		}
	}
}
