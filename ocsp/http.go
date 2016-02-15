package ocsp

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
)

const (
	// defaultGoUserAgent is the Go HTTP package user agent string. Too
	// bad it isn't exported. If it changes, we should update it here, too.
	defaultGoUserAgent = "Go-http-client/1.1"

	// ourUserAgent is the User-Agent of this underlying library package.
	ourUserAgent = "xenolf-ocsp"
)

// httpPost performs a POST request with a proper User-Agent string.
// Callers should close resp.Body when done reading from it.
func httpPost(url string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	req.Header.Set("User-Agent", userAgent())

	return http.DefaultClient.Do(req)
}

// httpGet performs a GET request with a proper User-Agent string.
// Callers should close resp.Body when done reading from it.
func httpGet(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())

	return http.DefaultClient.Do(req)
}

// userAgent builds and returns the User-Agent string to use in requests.
func userAgent() string {
	return fmt.Sprintf("%s (%s; %s) %s", defaultGoUserAgent, runtime.GOOS, runtime.GOARCH, ourUserAgent)
}
