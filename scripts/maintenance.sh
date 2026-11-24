#!/usr/bin/env bash
# Runs every check docs/maintenance.md lists, in order, and prints a summary.
# Nothing is written outside the repo. Exit code 1 means a check failed.
#
# Usage: ./scripts/maintenance.sh [--quick]
#   --quick  skip the benchmarks (about 20 s faster)

set -uo pipefail
cd "$(dirname "$0")/.."

quick=0
[ "${1:-}" = "--quick" ] && quick=1

fail=0
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
ok()   { printf '  \033[32mok\033[0m %s\n' "$1"; }

step "version baseline"
printf '  betterleaks: %s\n' "$(grep -o 'betterleaks/v2 v[^ ]*' go.mod | awk '{print $2}')"
printf '  minVersion : %s\n' "$(grep -o 'minVersion = "[^"]*"' internal/detector/rules/proxy.toml | cut -d'"' -f2)"
printf '  adapters   : %s\n' "$(grep -h '^id: ' internal/protocol/protocols/*.yaml | grep -vc '^id: _')"
printf '  rules      : %s\n' "$(grep -c '^id = ' internal/detector/rules/proxy.toml)"
printf '  eval cases : %s\n' "$(python3 -c 'import json;print(len(json.load(open("internal/detector/testdata/eval.json"))["cases"]))' 2>/dev/null || echo '?')"

step "minVersion is not behind go.mod"
want=$(grep -o 'betterleaks/v2 v[^ ]*' go.mod | awk '{print $2}')
have=$(grep -o 'minVersion = "[^"]*"' internal/detector/rules/proxy.toml | cut -d'"' -f2)
if [ "$want" = "$have" ]; then ok "$want"; else bad "go.mod $want != minVersion $have"; fi

step "build"
if go build ./... ; then ok "build"; else bad "build"; fi

step "vet"
if go vet ./... ; then ok "vet"; else bad "vet"; fi

step "gofmt"
unformatted=$(gofmt -l . 2>/dev/null)
if [ -z "$unformatted" ]; then ok "gofmt"; else bad "unformatted: $unformatted"; fi

step "tests (race)"
if go test -race -count=1 ./... >/tmp/kcmaint-test.log 2>&1; then
  ok "all packages"
else
  bad "see /tmp/kcmaint-test.log"; tail -30 /tmp/kcmaint-test.log
fi

step "detection quality"
if go test ./internal/detector -run 'EmbeddedRuleTests|EvalCorpus' -v 2>&1 | tee /tmp/kcmaint-eval.log | grep -q '^--- FAIL'; then
  bad "rules or eval corpus"; grep -E '^\s+eval_test|^--- FAIL' /tmp/kcmaint-eval.log | head -20
else
  ok "$(grep -o 'precision [0-9.]* recall [0-9.]*' /tmp/kcmaint-eval.log | tail -1)"
fi

if [ "$quick" = 0 ]; then
  step "throughput (baseline: scan >= 300 MB/s, chat >= 100 MB/s)"
  go test ./internal/detector -run xxx -bench BenchmarkScan100KB -benchtime 100x 2>&1 | grep -E 'Benchmark|MB/s' | sed 's/^/  /'
  go test ./internal/rewrite  -run xxx -bench BenchmarkChat64KB  -benchtime 50x  2>&1 | grep -E 'Benchmark|MB/s' | sed 's/^/  /'
fi

step "adapters"
go run ./cmd/keycordon adapters 2>/dev/null | sed 's/^/  /' | head -40

step "result"
if [ "$fail" = 0 ]; then
  printf '  \033[32mall checks passed\033[0m\n'
  exit 0
fi
printf '  \033[31msome checks failed\033[0m — see above, then update docs/maintenance.md section 5\n'
exit 1
