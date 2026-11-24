// Command keycordon is a reverse proxy that keeps secrets out of AI API
// requests and restores them in responses.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitlab.soraharu.com/XiaoXi/keycordon/internal/config"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/detector"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/protocol"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/proxy"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/vault"
	"gitlab.soraharu.com/XiaoXi/keycordon/internal/veto"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

const usage = `keycordon - keep secrets out of AI API requests

Usage:
  keycordon serve   [-config FILE] [-listen ADDR] [-upstream URL]
  keycordon scan    [-config FILE] [FILE]     replace secrets in FILE or stdin and print the result
  keycordon adapters                          list protocol adapters
  keycordon version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "scan":
		err = scan(os.Args[2:])
	case "adapters":
		err = adapters(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("keycordon", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keycordon:", err)
		os.Exit(1)
	}
}

func newLogger(c *config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Log.Level)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Log.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func loadConfig(fs *flag.FlagSet, args []string, extra func()) (*config.Config, error) {
	path := fs.String("config", "", "configuration file (YAML)")
	extra()
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func newDetector(c *config.Config, log *slog.Logger) (*detector.Detector, error) {
	return detector.New(detector.Options{
		RulesFile:      c.Detector.RulesFile,
		MaxDecodeDepth: *c.Detector.MaxDecodeDepth,
		MinValueLength: c.Detector.MinValueLength,
		Logger:         log,
	})
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var listen, upstream *string
	c, err := loadConfig(fs, args, func() {
		listen = fs.String("listen", "", "listen address (overrides config)")
		upstream = fs.String("upstream", "", "upstream base URL (overrides config)")
	})
	if err != nil {
		return err
	}
	if *listen != "" {
		c.Listen = *listen
	}
	if *upstream != "" {
		c.Upstream = *upstream
	}
	if err := c.Validate(); err != nil {
		return err
	}
	log := newLogger(c)

	key, err := vault.LoadMasterKey(vault.KeySource{
		Scope:   vault.Scope(c.Vault.MasterKeyScope),
		File:    c.Vault.MasterKeyFile,
		EnvName: c.Vault.MasterKeyEnv,
	})
	if err != nil {
		return err
	}
	fp := vault.Fingerprint(key)
	extraDir, err := vault.ExpandHome(c.Protocols.ExtraDir)
	if err != nil {
		return err
	}
	reg, err := protocol.Load(protocol.Options{Enabled: c.Protocols.Enabled, ExtraDir: extraDir})
	if err != nil {
		return err
	}
	t0 := time.Now()
	det, err := newDetector(c, log)
	if err != nil {
		return err
	}
	v := vault.New(key, vault.Options{MaxEntriesPerCaller: c.Vault.MaxEntriesPerCaller, IdleTTL: c.Vault.IdleTTL})
	clear(key)
	srv, err := proxy.New(proxy.Options{
		Config: c, Registry: reg, Detector: det, Vault: v, KeyFP: fp, Version: version, Logger: log,
	})
	if err != nil {
		return err
	}
	if !c.ListenIsLoopback() && !*c.Caller.RequireOnNonLoopback {
		log.Warn("listening on a non-loopback address without caller identification: all clients share one vault")
	}

	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Run(ctx)
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	log.Info("keycordon listening", "listen", ln.Addr().String(), "upstream", c.Upstream, "mode", c.Mode,
		"adapters", len(reg.Adapters()), "rules_hash", det.RulesHash(), "master_key_fingerprint", fp,
		"master_key_scope", c.Vault.MasterKeyScope, "startup_ms", time.Since(t0).Milliseconds())
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

// scan replaces secrets in a text file. Placeholders use a throwaway key.
func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	c, err := loadConfig(fs, args, func() {})
	if err != nil {
		return err
	}
	var in io.Reader = os.Stdin
	if fs.NArg() > 0 {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	det, err := newDetector(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	key, _ := vault.LoadMasterKey(vault.KeySource{Scope: vault.ScopeProcess})
	caller := vault.New(key, vault.Options{}).Caller("scan")
	text := string(data)
	hits, err := det.ScanOne(context.Background(), text)
	if err != nil {
		return err
	}
	var b strings.Builder
	prev, n := 0, 0
	for _, h := range hits {
		// The proxy also vetoes code, paths, versions and moments; scan
		// must report what the proxy would actually do (design 4.3.1).
		if veto.Reject(text, h.Start, h.End) {
			continue
		}
		b.WriteString(text[prev:h.Start])
		b.WriteString(caller.Placeholder(h.Value))
		prev = h.End
		n++
		fmt.Fprintf(os.Stderr, "%s\tline %d\tlen %d\n", h.RuleID, strings.Count(text[:h.Start], "\n")+1, len(h.Value))
	}
	b.WriteString(text[prev:])
	fmt.Print(b.String())
	fmt.Fprintf(os.Stderr, "%d secret(s) replaced\n", n)
	return nil
}

func adapters(args []string) error {
	fs := flag.NewFlagSet("adapters", flag.ExitOnError)
	c, err := loadConfig(fs, args, func() {})
	if err != nil {
		return err
	}
	extraDir, _ := vault.ExpandHome(c.Protocols.ExtraDir)
	reg, err := protocol.Load(protocol.Options{Enabled: c.Protocols.Enabled, ExtraDir: extraDir})
	if err != nil {
		return err
	}
	for _, a := range reg.Adapters() {
		inst := "-"
		if a.Instruction != nil {
			inst = a.Instruction.Strategy
		}
		fmt.Printf("%-28s filter=%-11s scan=%-11s notice=%-16s restore=%v\n", a.ID, a.Filter, a.Scan, inst, a.Restore)
	}
	return nil
}
