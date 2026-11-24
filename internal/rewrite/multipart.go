package rewrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"slices"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
)

type mpPart struct {
	hdr  textproto.MIMEHeader
	data []byte
}

// Multipart rewrites the named text fields of a multipart/form-data body.
// File parts are copied unchanged. The body is rebuilt with the original
// boundary only when something was replaced.
func (rw *Rewriter) Multipart(ctx context.Context, a *protocol.Adapter, raw []byte, contentType string, c *vault.Caller) (Result, error) {
	res := Result{Body: raw, Replaced: map[string]int{}}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return res, fmt.Errorf("%w: bad multipart content type", ErrBadRequest)
	}
	boundary := params["boundary"]
	r := multipart.NewReader(bytes.NewReader(raw), boundary)
	var parts []mpPart
	var units []*unit
	var owners []int
	for {
		p, err := r.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return res, fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
		mp := mpPart{hdr: p.Header, data: data}
		if p.FileName() == "" && slices.Contains(a.MultipartFields, p.FormName()) {
			units = append(units, &unit{text: string(data), prefix: `"` + p.FormName() + `": "`})
			owners = append(owners, len(parts))
		}
		parts = append(parts, mp)
	}
	if len(units) == 0 {
		return res, nil
	}
	var texts []string
	for _, u := range units {
		texts = append(texts, u.prefix+u.text)
	}
	hits, err := rw.Detector.Scan(ctx, texts)
	if err != nil {
		return res, fmt.Errorf("detector: %w", err)
	}
	changed := false
	for i, u := range units {
		spans := rw.spans(u, hits[i], c)
		if len(spans) == 0 {
			continue
		}
		var b []byte
		prev := 0
		for _, s := range spans {
			b = append(b, u.text[prev:s.start]...)
			b = append(b, c.Placeholder(u.text[s.start:s.end])...)
			prev = s.end
			res.Replaced[s.rule]++
		}
		b = append(b, u.text[prev:]...)
		parts[owners[i]].data = b
		changed = true
	}
	if !changed {
		return res, nil
	}
	var out bytes.Buffer
	w := multipart.NewWriter(&out)
	if err := w.SetBoundary(boundary); err != nil {
		return res, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	for _, p := range parts {
		pw, err := w.CreatePart(p.hdr)
		if err != nil {
			return res, err
		}
		pw.Write(p.data)
	}
	if err := w.Close(); err != nil {
		return res, err
	}
	res.Body = out.Bytes()
	return res, nil
}
