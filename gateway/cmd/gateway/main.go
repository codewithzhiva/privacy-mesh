package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/codewithzhiva/privacy-mesh/gateway/internal/policy"
)

type audit struct {
	mu      sync.Mutex
	byType  map[string]uint64
	actions map[string]uint64
}
type inspectRequest struct {
	Text       string `json:"text"`
	Action     string `json:"action"`
	Contextual bool   `json:"contextual"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	stats := &audit{byType: map[string]uint64{}, actions: map[string]uint64{}}
	analyzer := env("ANALYZER_URL", "http://localhost:8001")
	upstream := env("UPSTREAM_URL", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, map[string]string{"status": "ready"}) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for action, total := range stats.actions {
			fmt.Fprintf(w, "privacymesh_actions_total{action=%q} %d\n", action, total)
		}
		for entity, total := range stats.byType {
			fmt.Fprintf(w, "privacymesh_detections_total{entity=%q} %d\n", entity, total)
		}
	})
	mux.HandleFunc("/v1/inspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var input inspectRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&input); err != nil {
			respond(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		findings := policy.Detect(input.Text)
		if input.Contextual {
			findings = append(findings, analyze(r.Context(), analyzer, input.Text)...)
		}
		action := input.Action
		if action == "" {
			action = "redact"
		}
		stats.record(action, findings)
		switch action {
		case "allow":
			respond(w, 200, map[string]any{"action": "allow", "text": input.Text, "findings": safe(findings)})
		case "redact", "tokenize":
			respond(w, 200, map[string]any{"action": action, "text": policy.Redact(input.Text, findings), "findings": safe(findings)})
		case "block":
			if len(findings) > 0 {
				respond(w, 403, map[string]any{"action": "block", "findings": safe(findings)})
				return
			}
			respond(w, 200, map[string]any{"action": "allow", "text": input.Text})
		case "review":
			respond(w, 202, map[string]any{"action": "review", "text": policy.Redact(input.Text, findings), "findings": safe(findings)})
		default:
			respond(w, 422, map[string]string{"error": "unknown action"})
		}
	})
	mux.HandleFunc("/v1/audit/summary", func(w http.ResponseWriter, _ *http.Request) {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		respond(w, 200, map[string]any{"detections": stats.byType, "actions": stats.actions})
	})
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		if upstream == "" {
			respond(w, 503, map[string]string{"error": "UPSTREAM_URL is not configured"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			return
		}
		findings := policy.Detect(string(body))
		if len(findings) > 0 {
			stats.record("block", findings)
			respond(w, 403, map[string]any{"action": "block", "findings": safe(findings)})
			return
		}
		target, _ := url.Parse(upstream)
		request, _ := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
		request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			respond(w, 502, map[string]string{"error": "upstream unavailable"})
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			if strings.EqualFold(key, "Set-Cookie") {
				continue
			}
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(response.Body, 8<<20))
	})
	server := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info("gateway listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func analyze(ctx context.Context, base, text string) []policy.Finding {
	body, _ := json.Marshal(map[string]string{"text": text})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/analyze", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	var output struct {
		Findings []policy.Finding `json:"findings"`
	}
	if response.StatusCode == 200 {
		_ = json.NewDecoder(response.Body).Decode(&output)
	}
	return output.Findings
}
func safe(findings []policy.Finding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{"type": f.Type, "fingerprint": f.Fingerprint})
	}
	return out
}
func (a *audit) record(action string, findings []policy.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions[action]++
	for _, finding := range findings {
		a.byType[finding.Type]++
	}
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
