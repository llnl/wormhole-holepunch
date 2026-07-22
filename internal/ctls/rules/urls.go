package rules

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// Only allow HTTP and HTTPS schemes
	allowedSchemes = map[string]bool{
		"http":  true,
		"https": true,
	}

	// Block dangerous hostnames (case-insensitive)
	blockedHostPatterns = []string{
		"localhost",
		"kubernetes.default",
		".internal",
	}
)

func ValidateURL(str string, enforceResolution bool) (*url.URL, error) {
	if maximumHeader(str) {
		return nil, errors.New("proposed URL surpassed maximum header size")
	}

	parsed, err := url.Parse(str)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Validate scheme (only http/https)
	scheme := strings.ToLower(parsed.Scheme)
	if !allowedSchemes[scheme] {
		return nil, fmt.Errorf("unsupported URL scheme '%s': only http and https allowed", parsed.Scheme)
	}

	// Validate hostname exists
	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, errors.New("URL must have a hostname")
	}

	if enforceResolution {
		// Block private/internal addresses
		if err := validatePublicURL(hostname); err != nil {
			return nil, fmt.Errorf("invalid destination URL: %w", err)
		}
	}

	return parsed, nil
}

//

func validatePublicURL(hostname string) error {
	hostLower := strings.ToLower(hostname)

	// Check blocked hostname patterns
	for _, blocked := range blockedHostPatterns {
		if strings.Contains(hostLower, blocked) {
			return fmt.Errorf("hostname '%s' matches blocked pattern '%s'", hostname, blocked)
		}
	}

	// Resolve hostname to IPs
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// DNS resolution failure - reject for security
		return fmt.Errorf("cannot resolve hostname '%s': %w", hostname, err)
	}

	// Validate all resolved IPs are public
	for _, ip := range ips {
		if err := validatePublicIP(ip); err != nil {
			return fmt.Errorf("hostname '%s' resolves to invalid IP %s: %w", hostname, ip, err)
		}
	}

	return nil
}

func validatePublicIP(ip net.IP) error {
	// Block loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return errors.New("loopback addresses not allowed")
	}

	// Block link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return errors.New("link-local addresses not allowed")
	}

	// Block unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return errors.New("unspecified addresses not allowed")
	}

	return nil
}
