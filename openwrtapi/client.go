package openwrtapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func Call(socketPath, operation string, body []byte) ([]byte, error) {
	method := http.MethodGet
	path := "/v1/" + operation
	switch operation {
	case "status", "config":
	case "set-config":
		method = http.MethodPut
		path = "/v1/config"
	case "run":
		method = http.MethodPost
	default:
		return nil, fmt.Errorf("unsupported OpenWrt operation %q", operation)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	req, err := http.NewRequest(method, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OpenWrt API returned %s: %s", resp.Status, bytes.TrimSpace(result))
	}
	return result, nil
}
