package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// normalizeURL ensures scheme and brackets IPv6 hosts.
func normalizeURL(raw string) string {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	idx := strings.Index(raw, "://")
	if idx == -1 {
		return raw
	}
	scheme := raw[:idx+3]
	rest := raw[idx+3:]
	slash := strings.Index(rest, "/")
	host := rest
	path := ""
	if slash != -1 {
		host = rest[:slash]
		path = rest[slash:]
	}
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	if ip := net.ParseIP(strings.Trim(hostOnly, "[]")); ip != nil && ip.To4() == nil {
		if !strings.HasPrefix(host, "[") {
			host = "[" + hostOnly + "]"
		}
	}
	return scheme + host + path
}

// The shared enumeration client keeps TLS verification enabled and will not
// follow a redirect away from the authorized origin being inspected.
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 || (len(via) > 0 &&
			(next.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(next.URL.Host, via[0].URL.Host))) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// maxFingerprintBodyBytes limits responses to prevent unbounded memory use.
const maxFingerprintBodyBytes int64 = 4 << 20

// TLS verification stays enabled. For IP-based requests with a declared hostname,
// use that hostname for certificate validation as well as the HTTP Host header.
var newTransport = func(hostHeader string) *http.Transport {
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		Proxy:       http.ProxyFromEnvironment,
	}
	if hostHeader != "" {
		tr.TLSClientConfig = &tls.Config{ServerName: hostHeader}
	}
	return tr
}

func doRequest(rawURL string, hostHeader string) (*http.Response, []byte, error) {
	u := normalizeURL(rawURL)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if hostHeader != "" {
		req.Host = hostHeader
	}

	client := &http.Client{
		Transport: newTransport(hostHeader),
		Timeout:   10 * time.Second,
		// Do not follow redirects to a different host without authorization.
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= 10 || (len(via) > 0 && (next.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(next.URL.Host, via[0].URL.Host))) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBodyBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read fingerprint response: %w", err)
	}
	if int64(len(body)) > maxFingerprintBodyBytes {
		return nil, nil, fmt.Errorf("fingerprint response exceeds %d bytes", maxFingerprintBodyBytes)
	}
	return resp, body, nil
}

func Fingerprint(url string) (map[string]struct{}, *http.Response, []byte) {
	client, _ := wappalyzer.New()

	resp, body, err := doRequest(url, "")
	if err != nil {
		httpURL := strings.Replace(normalizeURL(url), "https://", "http://", 1)
		resp, body, err = doRequest(httpURL, "")
		if err != nil {
			return nil, nil, nil
		}
	}

	fp := client.Fingerprint(resp.Header, body)
	if _, ok := fp["WordPress"]; !ok {
		s := string(body)
		if strings.Contains(s, "/wp-content/") || strings.Contains(s, "/wp-includes/") {
			fp["WordPress"] = struct{}{}
		}
	}
	return fp, resp, body
}

func FingerprintWithIP(ip, host string) (map[string]struct{}, *http.Response, []byte) {
	client, _ := wappalyzer.New()

	target := ip
	if parsed := net.ParseIP(strings.Trim(ip, "[]")); parsed != nil && parsed.To4() == nil {
		target = "[" + strings.Trim(ip, "[]") + "]"
	}

	resp, body, err := doRequest("https://"+target, host)
	if err != nil {
		resp, body, err = doRequest("http://"+target, host)
		if err != nil {
			return nil, nil, nil
		}
	}

	fp := client.Fingerprint(resp.Header, body)
	if _, ok := fp["WordPress"]; !ok {
		s := string(body)
		if strings.Contains(s, "/wp-content/") || strings.Contains(s, "/wp-includes/") {
			fp["WordPress"] = struct{}{}
		}
	}
	return fp, resp, body
}

func ResolveIP(domain string) string {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ips[0].String()
}

func CheckXMLRPC(rawURL string) bool {
	u := normalizeURL(rawURL)
	client := &http.Client{Timeout: 5 * time.Second, Transport: newTransport("")}

	req, err := http.NewRequest("POST", u, strings.NewReader(`<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == 200 || resp.StatusCode == 405
}
