package protocol

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed protocols/*.yaml
var builtinFS embed.FS

// Registry holds the adapters in match order.
type Registry struct {
	adapters []*Adapter
}

// Options selects adapters.
type Options struct {
	// Enabled lists adapter IDs to keep; empty keeps all.
	Enabled []string
	// ExtraDir holds YAML files that add adapters or replace built-in ones
	// with the same ID.
	ExtraDir string
}

// Load builds the registry from the embedded adapters plus opts.ExtraDir.
func Load(opts Options) (*Registry, error) {
	specs, order, err := readDir(builtinFS, "protocols")
	if err != nil {
		return nil, err
	}
	if opts.ExtraDir != "" {
		if _, err := os.Stat(opts.ExtraDir); err == nil {
			extra, extraOrder, err := readDir(os.DirFS(opts.ExtraDir), ".")
			if err != nil {
				return nil, err
			}
			for _, id := range extraOrder {
				if _, ok := specs[id]; !ok {
					// New adapters take precedence over built-ins.
					order = append([]string{id}, order...)
				}
				specs[id] = extra[id]
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	enabled := map[string]bool{}
	for _, id := range opts.Enabled {
		if _, ok := specs[id]; !ok {
			return nil, fmt.Errorf("protocol: unknown adapter %q", id)
		}
		enabled[id] = true
	}
	r := &Registry{}
	for _, id := range order {
		s, err := resolve(specs, id, nil)
		if err != nil {
			return nil, fmt.Errorf("protocol %s: %w", id, err)
		}
		if s.Abstract || (len(enabled) > 0 && !enabled[id]) {
			continue
		}
		a, err := compile(s)
		if err != nil {
			return nil, fmt.Errorf("protocol %s: %w", id, err)
		}
		r.adapters = append(r.adapters, a)
	}
	return r, nil
}

// readDir parses every *.yaml file. A file may hold several documents.
// Order follows file names, then document order.
func readDir(fsys fs.FS, dir string) (map[string]*Spec, []string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil, err
	}
	specs := map[string]*Spec{}
	var order []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(fsys, filepath.ToSlash(filepath.Join(dir, e.Name())))
		if err != nil {
			return nil, nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		for {
			var s Spec
			if err := dec.Decode(&s); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, nil, fmt.Errorf("protocol: %s: %w", e.Name(), err)
			}
			if s.ID == "" {
				return nil, nil, fmt.Errorf("protocol: %s: adapter without id", e.Name())
			}
			if _, dup := specs[s.ID]; dup {
				return nil, nil, fmt.Errorf("protocol: duplicate adapter id %q", s.ID)
			}
			specs[s.ID] = &s
			order = append(order, s.ID)
		}
	}
	return specs, order, nil
}

// resolve merges extended specs: lists are concatenated (parents first),
// scalars and the instruction are taken from the child when set.
func resolve(specs map[string]*Spec, id string, stack []string) (*Spec, error) {
	if slices.Contains(stack, id) {
		return nil, fmt.Errorf("extends cycle: %s", strings.Join(append(stack, id), " -> "))
	}
	s, ok := specs[id]
	if !ok {
		return nil, fmt.Errorf("unknown adapter %q", id)
	}
	out := Spec{}
	for _, parent := range s.Extends {
		p, err := resolve(specs, parent, append(stack, id))
		if err != nil {
			return nil, err
		}
		merge(&out, p)
	}
	merge(&out, s)
	out.ID, out.Abstract, out.Extends = s.ID, s.Abstract, nil
	if len(s.Match) > 0 {
		out.Match = s.Match
	}
	return &out, nil
}

func merge(dst, src *Spec) {
	dst.Match = append(dst.Match, src.Match...)
	if src.Filter != "" {
		dst.Filter = src.Filter
	}
	dst.Multipart = dst.Multipart || src.Multipart
	r, sr := &dst.Request, &src.Request
	if sr.Scan != "" {
		r.Scan = sr.Scan
	}
	r.Fields = append(r.Fields, sr.Fields...)
	r.Frozen = append(r.Frozen, sr.Frozen...)
	r.Payload = append(r.Payload, sr.Payload...)
	r.KnownOnly = append(r.KnownOnly, sr.KnownOnly...)
	r.MultipartFields = append(r.MultipartFields, sr.MultipartFields...)
	if sr.Instruction != nil {
		r.Instruction = sr.Instruction
	}
	p, sp := &dst.Response, &src.Response
	if sp.Restore != "" {
		p.Restore = sp.Restore
	}
	p.Skip = append(p.Skip, sp.Skip...)
	p.JSONArrayStream = p.JSONArrayStream || sp.JSONArrayStream
	p.NDJSONStream = p.NDJSONStream || sp.NDJSONStream
	p.Deltas = append(p.Deltas, sp.Deltas...)
	p.StreamKeys = append(p.StreamKeys, sp.StreamKeys...)
	p.EndEvents = append(p.EndEvents, sp.EndEvents...)
}

// NormalizePath folds repeated slashes and drops a trailing slash.
func NormalizePath(p string) string {
	if !strings.Contains(p, "//") && (len(p) <= 1 || !strings.HasSuffix(p, "/")) {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '/' && b.Len() > 0 && strings.HasSuffix(b.String(), "/") {
			continue
		}
		b.WriteByte(p[i])
	}
	s := b.String()
	if len(s) > 1 {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

// Match returns the first adapter for the request, or nil.
func (r *Registry) Match(method, path string, upgrade bool) *Adapter {
	path = NormalizePath(path)
	for _, a := range r.adapters {
		if a.Matches(method, path, upgrade) {
			return a
		}
	}
	return nil
}

// Adapters returns the compiled adapters in match order.
func (r *Registry) Adapters() []*Adapter { return slices.Clone(r.adapters) }

// BuiltinFS exposes the embedded adapter files.
func BuiltinFS() fs.FS {
	sub, _ := fs.Sub(builtinFS, "protocols")
	return sub
}
