// Package protocol loads the declarative adapters that describe which AI
// endpoints keycordon filters and how their bodies are structured. Core code
// contains no provider-specific logic; everything lives in protocols/*.yaml.
package protocol

import (
	"fmt"
	"regexp"
	"strings"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/pathpat"
)

// Filter modes.
const (
	FilterOn          = "on"
	FilterUnsupported = "unsupported"
)

// Scan modes.
const (
	ScanAllStrings = "all_strings"
	ScanFields     = "fields"
)

// Delta kinds.
const (
	KindText         = "text"
	KindJSONFragment = "json_fragment"
	KindReasoning    = "reasoning"
)

// Instruction strategies.
const (
	InstrOpenAIMessages = "openai_messages"
	InstrString         = "string"
	InstrStringOrBlocks = "string_or_blocks"
	InstrGemini         = "gemini"
	// InstrResponsesInput prepends a developer message to an "input" array
	// and falls back to InstrString on "instructions" otherwise.
	InstrResponsesInput = "responses_input"
)

// Spec is the YAML form of an adapter.
type Spec struct {
	ID       string      `yaml:"id"`
	Extends  []string    `yaml:"extends"`
	Abstract bool        `yaml:"abstract"`
	Match    []MatchSpec `yaml:"match"`
	Filter   string      `yaml:"filter"`
	// Multipart enables multipart/form-data bodies; only text parts named
	// in Request.MultipartFields are scanned.
	Multipart bool         `yaml:"multipart"`
	Request   RequestSpec  `yaml:"request"`
	Response  ResponseSpec `yaml:"response"`
}

// MatchSpec matches a request before its body is read.
type MatchSpec struct {
	Method     string `yaml:"method"`
	PathSuffix string `yaml:"path_suffix"`
	// PathRegex is matched case-insensitively against the end of the path.
	PathRegex string `yaml:"path_regex"`
	// Upgrade matches only WebSocket upgrade requests when true.
	Upgrade bool `yaml:"upgrade"`
}

// RequestSpec describes the request body.
type RequestSpec struct {
	Scan   string   `yaml:"scan"`
	Fields []string `yaml:"fields"`
	// Frozen leaves are never scanned or changed.
	Frozen []string `yaml:"frozen"`
	// Payload marks user-defined objects (tool inputs, schemas) inside which
	// Frozen does not apply, so keys like "id" or "name" there are scanned.
	Payload []string `yaml:"payload"`
	// KnownOnly leaves are only checked against already-known secrets.
	KnownOnly       []string         `yaml:"known_only"`
	MultipartFields []string         `yaml:"multipart_fields"`
	Instruction     *InstructionSpec `yaml:"instruction"`
}

// InstructionSpec says where the placeholder notice goes.
type InstructionSpec struct {
	Strategy string `yaml:"strategy"`
	// Path is the dotted member path of the target, e.g. "system" or
	// "request.systemInstruction". Alternatives are separated by "|".
	Path string `yaml:"path"`
}

// ResponseSpec describes responses.
type ResponseSpec struct {
	// Restore is "all_strings" (default) or "none".
	Restore string   `yaml:"restore"`
	Skip    []string `yaml:"skip"`
	// JSONArrayStream enables incremental restore of streamed JSON arrays
	// (Gemini streamGenerateContent without alt=sse).
	JSONArrayStream bool `yaml:"json_array_stream"`
	// NDJSONStream enables incremental restore of newline-delimited JSON
	// streams (Ollama native API).
	NDJSONStream bool        `yaml:"ndjson_stream"`
	Deltas       []DeltaSpec `yaml:"deltas"`
	// StreamKeys are root members whose values identify a stream, e.g.
	// "index" for Anthropic or "item_id" for Responses.
	StreamKeys []string `yaml:"stream_keys"`
	EndEvents  []string `yaml:"end_events"`
}

// DeltaSpec declares an incremental string field in a streamed event.
type DeltaSpec struct {
	// Event matches the SSE event name or the root "type" member; empty
	// matches any event.
	Event string `yaml:"event"`
	Field string `yaml:"field"`
	Kind  string `yaml:"kind"`
}

// Adapter is a compiled Spec.
type Adapter struct {
	ID        string
	Filter    string
	Multipart bool
	match     []matcher

	Scan            string
	Fields          pathpat.Set
	Frozen          pathpat.Set
	Payload         pathpat.Set
	KnownOnly       pathpat.Set
	MultipartFields []string
	Instruction     *InstructionSpec

	Restore         bool
	Skip            pathpat.Set
	JSONArrayStream bool
	NDJSONStream    bool
	Deltas          []Delta
	StreamKeys      []string
	EndEvents       map[string]bool
}

// Delta is a compiled DeltaSpec.
type Delta struct {
	Event string
	Field *pathpat.Pattern
	Kind  string
}

type matcher struct {
	method  string
	suffix  string
	re      *regexp.Regexp
	upgrade bool
}

func compile(s *Spec) (*Adapter, error) {
	a := &Adapter{
		ID:              s.ID,
		Filter:          s.Filter,
		Multipart:       s.Multipart,
		Scan:            s.Request.Scan,
		MultipartFields: s.Request.MultipartFields,
		Instruction:     s.Request.Instruction,
		Restore:         s.Response.Restore != "none",
		JSONArrayStream: s.Response.JSONArrayStream,
		NDJSONStream:    s.Response.NDJSONStream,
		StreamKeys:      s.Response.StreamKeys,
		EndEvents:       map[string]bool{},
	}
	if a.Filter == "" {
		a.Filter = FilterOn
	}
	if a.Filter != FilterOn && a.Filter != FilterUnsupported {
		return nil, fmt.Errorf("filter must be %q or %q", FilterOn, FilterUnsupported)
	}
	if a.Scan == "" {
		a.Scan = ScanAllStrings
	}
	if a.Scan != ScanAllStrings && a.Scan != ScanFields {
		return nil, fmt.Errorf("unknown scan mode %q", a.Scan)
	}
	if a.Scan == ScanFields && len(s.Request.Fields) == 0 && len(s.Request.MultipartFields) == 0 && a.Filter == FilterOn {
		return nil, fmt.Errorf("scan: fields needs request.fields")
	}
	if len(s.Match) == 0 {
		return nil, fmt.Errorf("no match rules")
	}
	for _, m := range s.Match {
		mt := matcher{method: strings.ToUpper(m.Method), suffix: strings.ToLower(m.PathSuffix), upgrade: m.Upgrade}
		if m.PathRegex != "" {
			re, err := regexp.Compile("(?i)(?:" + m.PathRegex + ")$")
			if err != nil {
				return nil, fmt.Errorf("path_regex: %w", err)
			}
			mt.re = re
		}
		if mt.suffix == "" && mt.re == nil {
			return nil, fmt.Errorf("match rule needs path_suffix or path_regex")
		}
		a.match = append(a.match, mt)
	}
	var err error
	sets := []struct {
		dst *pathpat.Set
		src []string
	}{
		{&a.Fields, s.Request.Fields}, {&a.Frozen, s.Request.Frozen}, {&a.Payload, s.Request.Payload},
		{&a.KnownOnly, s.Request.KnownOnly}, {&a.Skip, s.Response.Skip},
	}
	for _, x := range sets {
		if *x.dst, err = pathpat.CompileSet(x.src); err != nil {
			return nil, err
		}
	}
	if in := a.Instruction; in != nil {
		switch in.Strategy {
		case InstrOpenAIMessages, InstrString, InstrStringOrBlocks, InstrGemini, InstrResponsesInput:
		default:
			return nil, fmt.Errorf("unknown instruction strategy %q", in.Strategy)
		}
		if in.Path == "" {
			return nil, fmt.Errorf("instruction.path is required")
		}
	}
	for _, d := range s.Response.Deltas {
		switch d.Kind {
		case KindText, KindJSONFragment, KindReasoning:
		default:
			return nil, fmt.Errorf("unknown delta kind %q", d.Kind)
		}
		p, err := pathpat.Compile(d.Field)
		if err != nil {
			return nil, err
		}
		a.Deltas = append(a.Deltas, Delta{Event: d.Event, Field: p, Kind: d.Kind})
	}
	for _, e := range s.Response.EndEvents {
		a.EndEvents[e] = true
	}
	return a, nil
}

// Matches reports whether the adapter handles the request.
func (a *Adapter) Matches(method, path string, upgrade bool) bool {
	lp := strings.ToLower(path)
	for _, m := range a.match {
		if m.method != "" && m.method != method {
			continue
		}
		if m.upgrade && !upgrade {
			continue
		}
		if m.suffix != "" && !strings.HasSuffix(lp, m.suffix) {
			continue
		}
		if m.re != nil && !m.re.MatchString(path) {
			continue
		}
		return true
	}
	return false
}
