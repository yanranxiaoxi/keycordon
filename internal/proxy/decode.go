package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var (
	errUnknownEncoding = errors.New("unsupported content encoding")
	errTooLarge        = errors.New("body too large")
)

// decodeBody removes every Content-Encoding layer (applied in reverse order)
// and limits the decoded size to protect against decompression bombs.
func decodeBody(body []byte, encodings []string, limit int64) ([]byte, error) {
	var layers []string
	for _, h := range encodings {
		for _, e := range strings.Split(h, ",") {
			e = strings.ToLower(strings.TrimSpace(e))
			if e != "" && e != "identity" {
				layers = append(layers, e)
			}
		}
	}
	for i := len(layers) - 1; i >= 0; i-- {
		var r io.Reader
		var closer func()
		switch layers[i] {
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, fmt.Errorf("gzip: %w", err)
			}
			r = zr
		case "deflate":
			if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
				r = zr
			} else {
				// Some clients send raw DEFLATE without the zlib wrapper.
				r = flate.NewReader(bytes.NewReader(body))
			}
		case "br":
			r = brotli.NewReader(bytes.NewReader(body))
		case "zstd":
			zr, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderMaxMemory(uint64(limit)+1))
			if err != nil {
				return nil, fmt.Errorf("zstd: %w", err)
			}
			r, closer = zr, zr.Close
		default:
			return nil, fmt.Errorf("%w: %s", errUnknownEncoding, layers[i])
		}
		out, err := io.ReadAll(io.LimitReader(r, limit+1))
		if closer != nil {
			closer()
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", layers[i], err)
		}
		if int64(len(out)) > limit {
			return nil, errTooLarge
		}
		body = out
	}
	return body, nil
}
