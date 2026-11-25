package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Requests are served concurrently: a slow upstream call must not hold up a
// fast one, which is the whole point of a reverse proxy in front of an API.
func TestConcurrentRequests(t *testing.T) {
	ps, up := newProxy(t, nil)
	const hold = 300 * time.Millisecond
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) {
		time.Sleep(hold)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}
	payload := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	const n = 8

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ps.URL+"/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()

	// Serialised would be n*hold (2.4 s); concurrent is about one hold.
	if el := time.Since(start); el > hold*3 {
		t.Errorf("%d requests took %v: they appear serialised", n, el)
	}
}

// SSE streams are relayed as they arrive, and several overlap.
func TestConcurrentStreams(t *testing.T) {
	ps, up := newProxy(t, nil)
	up.handler = func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 5; i++ {
			b, _ := json.Marshal(fmt.Sprintf("tok%d ", i))
			io.WriteString(w, `data: {"choices":[{"index":0,"delta":{"content":`+string(b)+`}}]}`+"\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}
	payload := []byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ps.URL+"/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()

	// One stream is ~500 ms; four serialised would be ~2 s.
	if el := time.Since(start); el > 1200*time.Millisecond {
		t.Errorf("4 streams took %v: they appear serialised", el)
	}
}
