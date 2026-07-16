// Package openwrtapi provides a local-only management API for LuCI.
package openwrtapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/dns"
)

const redactedSecret = "********"

type Server struct {
	Version   string
	StartedAt time.Time

	mu      sync.Mutex
	running bool
}

func NewServer(version string) *Server {
	return &Server{Version: version, StartedAt: time.Now()}
}

func (s *Server) Serve(socketPath string) error {
	if socketPath == "" {
		return errors.New("OpenWrt socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0660); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.status)
	mux.HandleFunc("/v1/config", s.configuration)
	mux.HandleFunc("/v1/run", s.run)
	return http.Serve(listener, mux)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    s.Version,
		"started_at": s.StartedAt.UTC().Format(time.RFC3339),
		"updating":   running,
	})
}

func (s *Server) configuration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		conf, err := config.GetConfigCached()
		if err != nil && !os.IsNotExist(err) {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		public := cloneConfig(conf)
		redactConfig(&public)
		writeJSON(w, http.StatusOK, public)
	case http.MethodPut:
		var next config.Config
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&next); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid configuration: %w", err))
			return
		}
		current, _ := config.GetConfigCached()
		mergeRedactedSecrets(&next, &current)
		next.Username = ""
		next.Password = ""
		next.NotAllowWanAccess = true
		if err := next.SaveConfig(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
	default:
		methodNotAllowed(w)
	}
}

func cloneConfig(source config.Config) config.Config {
	cloned := source
	cloned.DnsConf = append([]config.DnsConfig(nil), source.DnsConf...)
	for i := range cloned.DnsConf {
		cloned.DnsConf[i].Ipv4.Domains = append([]string(nil), source.DnsConf[i].Ipv4.Domains...)
		cloned.DnsConf[i].Ipv6.Domains = append([]string(nil), source.DnsConf[i].Ipv6.Domains...)
	}
	return cloned
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, errors.New("an update is already running"))
		return
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		dns.RunOnce()
	}()
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

func redactConfig(conf *config.Config) {
	conf.Username = ""
	conf.Password = ""
	for i := range conf.DnsConf {
		if conf.DnsConf[i].DNS.ID != "" {
			conf.DnsConf[i].DNS.ID = redactedSecret
		}
		if conf.DnsConf[i].DNS.Secret != "" {
			conf.DnsConf[i].DNS.Secret = redactedSecret
		}
	}
}

func mergeRedactedSecrets(next, current *config.Config) {
	for i := range next.DnsConf {
		if i >= len(current.DnsConf) {
			continue
		}
		if next.DnsConf[i].DNS.ID == redactedSecret {
			next.DnsConf[i].DNS.ID = current.DnsConf[i].DNS.ID
		}
		if next.DnsConf[i].DNS.Secret == redactedSecret {
			next.DnsConf[i].DNS.Secret = current.DnsConf[i].DNS.Secret
		}
	}
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
