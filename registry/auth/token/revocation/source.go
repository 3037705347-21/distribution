package revocation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// errNotModified signals that a source confirmed the document has not
// changed since the previous fetch (HTTP 304).
var errNotModified = errors.New("revocation list not modified")

// Source provides the raw revocation list document. Implementations return
// the complete, current document bytes.
type Source interface {
	// Fetch returns the current document along with a commit function.
	// The caller invokes commit only after the document has been parsed
	// and accepted; it activates the conditional-request validators the
	// source received with this response (so that a rejected document is
	// re-fetched on the next refresh rather than masked as "not
	// modified"). commit may be nil. Fetch returns errNotModified when
	// the source confirms the document is unchanged.
	Fetch(ctx context.Context) (data []byte, commit func(), err error)
	// String identifies the source in log messages. Secrets embedded in
	// URL user info or query parameters must be redacted.
	String() string
}

// fileSource reads the document from a local file. Publishers are expected
// to replace the file atomically (write to a temporary file and rename).
type fileSource struct {
	path string
}

func newFileSource(path string) Source {
	return &fileSource{path: path}
}

func (s *fileSource) Fetch(_ context.Context) ([]byte, func(), error) {
	fp, err := os.Open(s.path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open revocation list file %q: %w", s.path, err)
	}
	defer fp.Close()

	// Bound the amount of memory a document can consume even before
	// Parse performs its definitive size check.
	data, err := io.ReadAll(io.LimitReader(fp, MaxListBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read revocation list file %q: %w", s.path, err)
	}
	if len(data) == 0 {
		return nil, nil, errors.New("revocation list is empty")
	}
	if len(data) > MaxListBytes {
		return nil, nil, fmt.Errorf("revocation list file %q exceeds maximum size of %d bytes", s.path, MaxListBytes)
	}

	return data, nil, nil
}

func (s *fileSource) String() string {
	return "file://" + s.path
}

// httpSource polls an HTTP(S) endpoint using conditional requests. Cached
// validators are committed only after a 200 response body has been accepted
// by the loader; a 304 response means the document is unchanged.
type httpSource struct {
	endpoint string
	logName  string
	client   *http.Client

	mu           sync.Mutex
	etag         string
	lastModified string
}

func newHTTPSource(endpoint string, timeout time.Duration) Source {
	logName := endpoint
	if parsed, err := url.Parse(endpoint); err == nil {
		logName = parsed.Redacted()
	}
	return &httpSource{
		endpoint: endpoint,
		logName:  logName,
		client:   &http.Client{Timeout: timeout},
	}
}

func (s *httpSource) Fetch(ctx context.Context) ([]byte, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build revocation list request: %w", err)
	}

	s.mu.Lock()
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	if s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}
	s.mu.Unlock()

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch revocation list from %q: %w", s.logName, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil, errNotModified
	case http.StatusOK:
	default:
		return nil, nil, fmt.Errorf("revocation list endpoint %q returned unexpected status %s", s.logName, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read revocation list response from %q: %w", s.logName, err)
	}
	if len(body) > MaxListBytes {
		return nil, nil, fmt.Errorf("revocation list from %q exceeds maximum size of %d bytes", s.logName, MaxListBytes)
	}

	// Validators are activated only once the body has been accepted.
	nextETag := resp.Header.Get("ETag")
	nextLastModified := resp.Header.Get("Last-Modified")
	commit := func() {
		s.mu.Lock()
		s.etag = nextETag
		s.lastModified = nextLastModified
		s.mu.Unlock()
	}

	return body, commit, nil
}

func (s *httpSource) String() string {
	return s.logName
}
