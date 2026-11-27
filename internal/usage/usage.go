// Package usage reads the token accounting an AI upstream reports in a
// response. It exists only for diagnostics: whether a prompt cache hit is
// decided by the cached token count, and that count is only visible here.
// Nothing in this package changes the traffic.
package usage

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// Info is the token accounting of one response. Providers name the same
// numbers differently; Merge folds each shape into this one.
//
// InputTokens is always the whole input, the cached part included:
// OpenAI's prompt_tokens and Gemini's promptTokenCount already are, and
// Anthropic's input_tokens is not, so it is summed up on the way in. That
// keeps one definition across providers, which is what the hit rate needs.
type Info struct {
	InputTokens  int64
	CachedTokens int64
	OutputTokens int64
	// CacheWriteTokens is the input that was written to the cache by this
	// request. Only Anthropic reports it.
	CacheWriteTokens int64
	Model            string
}

// Empty reports that nothing was found.
func (i Info) Empty() bool {
	return i.InputTokens == 0 && i.CachedTokens == 0 && i.OutputTokens == 0 &&
		i.CacheWriteTokens == 0 && i.Model == ""
}

// HitRate returns the share of the input that came from the prompt cache.
//
// Dividing by whatever the provider calls "input" is wrong for Anthropic,
// whose input_tokens excludes the cached part: a well-cached Claude request
// has input_tokens=18 against cache_read_input_tokens=48000, which reads as
// 266666%. Merge therefore normalises Anthropic to the OpenAI shape first.
func (i Info) HitRate() float64 {
	if i.InputTokens <= 0 {
		return 0
	}
	return float64(i.CachedTokens) / float64(i.InputTokens)
}

// wire is the union of the response shapes keycordon sees. Every field is
// optional: a provider that does not send a number leaves it at zero.
type wire struct {
	Model string `json:"model"`
	Usage *struct {
		// OpenAI Chat Completions.
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		// OpenAI Responses.
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
		PromptDetail *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
		InputDetail *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"input_tokens_details"`
		// Anthropic reports the cache separately from the input.
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
	// Gemini.
	UsageMetadata *struct {
		PromptTokenCount        int64 `json:"promptTokenCount"`
		CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
		CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
	} `json:"usageMetadata"`
}

// Merge adds what w reports, keeping earlier values when w repeats none of
// them: a stream reports input tokens in its first event and output tokens
// in its last.
func (i *Info) Merge(w wire) {
	if w.Model != "" {
		i.Model = w.Model
	}
	if u := w.Usage; u != nil {
		// Anthropic's three numbers are disjoint parts of one input; OpenAI's
		// and Gemini's are one total plus a detail of it. Adding them up only
		// for Anthropic keeps "InputTokens is the whole input" true for every
		// provider, which is what the hit rate divides by.
		if u.CacheReadInputTokens > 0 || u.CacheCreationInputTokens > 0 {
			var total int64
			for _, v := range []int64{u.InputTokens, u.CacheReadInputTokens, u.CacheCreationInputTokens} {
				total += v
			}
			set(&i.InputTokens, total)
			set(&i.CacheWriteTokens, u.CacheCreationInputTokens)
		} else {
			set(&i.InputTokens, u.PromptTokens, u.InputTokens)
		}
		set(&i.OutputTokens, u.CompletionTokens, u.OutputTokens)
		if u.PromptDetail != nil {
			set(&i.CachedTokens, u.PromptDetail.CachedTokens)
		}
		if u.InputDetail != nil {
			set(&i.CachedTokens, u.InputDetail.CachedTokens)
		}
		set(&i.CachedTokens, u.CacheReadInputTokens)
	}
	if m := w.UsageMetadata; m != nil {
		set(&i.InputTokens, m.PromptTokenCount)
		set(&i.OutputTokens, m.CandidatesTokenCount)
		set(&i.CachedTokens, m.CachedContentTokenCount)
	}
}

func set(dst *int64, vals ...int64) {
	for _, v := range vals {
		if v > 0 {
			*dst = v
			return
		}
	}
}

// key is the substring every payload carries; a line without it is never
// decoded.
var key = []byte(`"usage`)

// FromJSON extracts the accounting of a complete JSON body.
func FromJSON(b []byte) Info {
	var i Info
	observe(&i, b)
	return i
}

// observe reads one line, which is either a JSON document or an SSE data
// field holding one.
func observe(i *Info, line []byte) {
	if !bytes.Contains(line, key) {
		return
	}
	line = bytes.TrimSpace(line)
	if d := bytes.TrimPrefix(line, []byte("data:")); len(d) < len(line) {
		line = bytes.TrimSpace(d)
	}
	var w wire
	if err := json.Unmarshal(line, &w); err != nil {
		return
	}
	i.Merge(w)
}

// maxLine bounds one observed line. Usage objects are small, so a longer
// line is a payload fragment and is dropped unread.
const maxLine = 64 << 10

// Watch returns a body that observes its bytes as they pass and reports the
// accounting once, when the body is closed or ends.
func Watch(r io.ReadCloser, report func(Info)) io.ReadCloser {
	return &watcher{rc: r, report: report}
}

type watcher struct {
	rc     io.ReadCloser
	report func(Info)

	mu   sync.Mutex
	line []byte
	info Info
	once sync.Once
}

func (w *watcher) Read(p []byte) (int, error) {
	n, err := w.rc.Read(p)
	if n > 0 {
		w.scan(p[:n])
	}
	if err == io.EOF {
		w.emit()
	}
	return n, err
}

func (w *watcher) scan(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if len(w.line)+len(b) <= maxLine {
				w.line = append(w.line, b...)
			} else {
				w.line = w.line[:0]
			}
			return
		}
		w.line = append(w.line, b[:i]...)
		observe(&w.info, w.line)
		w.line = w.line[:0]
		b = b[i+1:]
	}
}

// emit publishes the accounting. A body that is one JSON document without a
// trailing newline is observed here.
func (w *watcher) emit() {
	w.once.Do(func() {
		w.mu.Lock()
		observe(&w.info, w.line)
		info := w.info
		w.line = nil
		w.mu.Unlock()
		if w.report != nil {
			w.report(info)
		}
	})
}

func (w *watcher) Close() error {
	w.emit()
	return w.rc.Close()
}
