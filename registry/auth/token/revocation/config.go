package revocation

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	// defaultInterval is used when Config.Interval is zero.
	defaultInterval = 60 * time.Second
	// defaultTimeout is the HTTP request timeout used when Config.Timeout
	// is zero.
	defaultTimeout = 10 * time.Second
	// minimumInterval bounds polling frequency.
	minimumInterval = time.Second
)

// Config configures a Loader. Exactly one of Path and URL must be set.
type Config struct {
	// Path is the location of a local revocation list file.
	Path string
	// URL is an http(s) endpoint serving the revocation list.
	URL string
	// Interval is the refresh polling interval. Zero uses the default.
	Interval time.Duration
	// Timeout bounds a single HTTP refresh request. Zero uses the default.
	Timeout time.Duration
}

// validate checks the configuration and applies defaults.
func (c *Config) validate() error {
	hasPath := c.Path != ""
	hasURL := c.URL != ""
	if hasPath == hasURL {
		return errors.New("revocation config requires exactly one of \"path\" or \"url\"")
	}

	if hasURL {
		parsed, err := url.Parse(c.URL)
		if err != nil {
			return fmt.Errorf("invalid revocation url %q: %w", c.URL, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("invalid revocation url %q: scheme must be http or https", c.URL)
		}
		if parsed.Host == "" {
			return fmt.Errorf("invalid revocation url %q: missing host", c.URL)
		}
	}

	if c.Interval == 0 {
		c.Interval = defaultInterval
	} else if c.Interval < 0 {
		return errors.New("revocation interval must not be negative")
	} else if c.Interval < minimumInterval {
		c.Interval = minimumInterval
	}

	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	} else if c.Timeout < 0 {
		return errors.New("revocation timeout must not be negative")
	}

	return nil
}
