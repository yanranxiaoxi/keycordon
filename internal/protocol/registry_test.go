package protocol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	r, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path string
		upgrade      bool
		want         string
	}{
		{"POST", "/v1/chat/completions", false, "openai-chat"},
		{"POST", "/api/paas/v4/chat/completions", false, "openai-chat"},
		{"POST", "//v1//chat/completions/", false, "openai-chat"},
		{"POST", "/V1/Chat/Completions", false, "openai-chat"},
		{"POST", "/v1/completions", false, "openai-completions"},
		{"POST", "/v1/responses", false, "openai-responses"},
		{"POST", "/backend-api/codex/responses", false, "openai-responses"},
		{"POST", "/v1/responses/compact", false, "openai-responses"},
		{"GET", "/v1/responses", true, "websocket-ai"},
		{"POST", "/v1/messages", false, "anthropic-messages"},
		{"POST", "/v1/messages/count_tokens", false, "anthropic-messages"},
		{"POST", "/v1/messages/batches", false, "anthropic-batches"},
		{"POST", "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4@20250514:streamRawPredict", false, "anthropic-messages"},
		{"POST", "/v1beta/models/gemini-2.5-pro:streamGenerateContent", false, "gemini"},
		{"POST", "/v1beta/models/gemini-2.5-pro:generateContent", false, "gemini"},
		{"POST", "/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:generateContent", false, "gemini"},
		{"POST", "/v1beta/tunedModels/foo/models/x:countTokens", false, "gemini"},
		{"POST", "/v1internal:streamGenerateContent", false, "gemini-cli"},
		{"POST", "/v1/embeddings", false, "openai-embeddings"},
		{"POST", "/v1/images/edits", false, "openai-images"},
		{"POST", "/v1/videos", false, "openai-videos"},
		{"POST", "/v1/videos/video_123/remix", false, "openai-videos"},
		{"POST", "/v1/audio/transcriptions", false, "openai-audio-transcription"},
		{"POST", "/v1/systemone", false, "litellm-systemone"},
		{"POST", "/v1/decisions", false, "litellm-decisions"},
		{"POST", "/api/chat", false, "ollama-chat"},
		// xAI's own TTS and Codex's standalone search (CLIProxyAPI routes).
		{"POST", "/v1/tts", false, "xai-tts"},
		{"POST", "/v1/alpha/search", false, "codex-alpha-search"},
		{"POST", "/backend-api/codex/alpha/search", false, "codex-alpha-search"},
		// Realtime HTTP control endpoints cannot be filtered.
		{"POST", "/v1/realtime", false, "openai-realtime-http"},
		{"POST", "/v1/realtime/calls", false, "openai-realtime-http"},
		{"POST", "/v1/realtime/calls/abc/hangup", false, "openai-realtime-http"},
		{"POST", "/v1/realtime/client_secrets", false, "openai-realtime-http"},
		{"GET", "/v1/realtime/translations", false, "openai-realtime-http"},
		{"GET", "/v1/realtime", true, "websocket-ai"},
		{"GET", "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent", true, "websocket-ai"},
		{"GET", "/v1/models", false, ""},
		{"GET", "/v1/videos/video_123", false, ""},
		{"POST", "/v1/files", false, ""},
		{"GET", "/v1/chat/completions", false, ""},
		{"POST", "/v0/management/config", false, ""},
	}
	for _, c := range cases {
		a := r.Match(c.method, c.path, c.upgrade)
		got := ""
		if a != nil {
			got = a.ID
		}
		if got != c.want {
			t.Errorf("%s %s upgrade=%v: got %q want %q", c.method, c.path, c.upgrade, got, c.want)
		}
	}
}

func TestExtendsMerge(t *testing.T) {
	r, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Adapters() {
		if a.ID == "gemini-cli" {
			if len(a.Frozen) < 30 || len(a.Payload) == 0 || len(a.Deltas) != 4 || !a.JSONArrayStream {
				t.Fatalf("gemini-cli not merged: frozen=%d payload=%d deltas=%d", len(a.Frozen), len(a.Payload), len(a.Deltas))
			}
			if a.Instruction == nil || a.Instruction.Path != "request.systemInstruction|request.system_instruction" {
				t.Fatal("instruction not taken from child")
			}
			return
		}
	}
	t.Fatal("gemini-cli missing")
}

func TestExtraDirOverride(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte(`
id: openai-chat
extends: [_common]
match:
  - method: POST
    path_suffix: /my/chat
---
id: custom-ai
extends: [_common]
match:
  - method: POST
    path_suffix: /chat/completions
`), 0o600)
	r, err := Load(Options{ExtraDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if a := r.Match("POST", "/x/my/chat", false); a == nil || a.ID != "openai-chat" {
		t.Fatalf("override not applied: %v", a)
	}
	if a := r.Match("POST", "/v1/chat/completions", false); a == nil || a.ID != "custom-ai" {
		t.Fatalf("new adapter should win: %v", a)
	}
	if _, err := Load(Options{Enabled: []string{"nope"}}); err == nil {
		t.Fatal("unknown enabled adapter accepted")
	}
}
