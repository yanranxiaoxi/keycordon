# 定期审查清单

keycordon 有三个外部依赖面会持续变化，任何一个落后都会导致「以为保护了、其实没有」：

1. **betterleaks** 的版本与规则集。检测能力完全由它决定，升级带来新规则，也可能改变规则行为。
2. **AI 端点**。上游和 CPA 会新增端点；没登记的端点默认透传，等于不保护。
3. **magpie 等同类实现的变更**。它们在打同样的补丁，踩过的坑可以直接借鉴，避免重复发现。

本文规定这三件事**怎么做**、**做完记录在哪**、**什么情况下必须立刻做**。

---

## 0. 节奏与触发条件

| 触发 | 动作 |
|---|---|
| 每月一次（建议固定在月初） | 完整跑一遍第 1～3 节 |
| `go test ./...` 出现 `minVersion` 相关失败 | 立刻做第 1 节 |
| Go 主版本升级（`go.mod` 的 `go` 行） | 同步 `Dockerfile` 的 `ARG GO_VERSION` 与 `.gitlab-ci.yml` 的 `golang:1.xx` 镜像 |
| 用户在真实使用中遇到「密钥没被替换」 | 立刻做第 1 节 + 补评估集用例 |
| 换用新的上游（新的模型厂商、新的 CPA 版本） | 立刻做第 2 节 |
| CPA 发版 | 做第 2 节（CPA 的路由表是端点清单的权威来源） |
| 想做第 4 节（编码/引用第三方检查） | 先做第 1～3 节 |

**一次完整审查的预算**：约 1.5～2 小时。第 1 节 40 分钟，第 2 节 40 分钟，第 3 节 20 分钟，第 5 节记录 10 分钟。

**先跑一遍脚本**，它能自动完成第 6 节的全部断言和本文的基线核对：

```sh
./scripts/maintenance.sh          # 约 40 秒，含基准测试
./scripts/maintenance.sh --quick  # 跳过基准测试
```

脚本失败就先修，再去人工做第 1～3 节。它打印的基线数字（betterleaks 版本、适配器数、规则数、评估集用例数）应当与本文件 §1.1 / §2.1 记录的一致。

---

## 1. betterleaks 版本与规则

### 1.1 当前基线

| 项 | 值 | 位置 |
|---|---|---|
| 依赖版本 | `v2.0.0-rc.9` | [go.mod](../go.mod) |
| 规则文件声明的最低版本 | `v2.0.0-rc.9` | [proxy.toml](../internal/detector/rules/proxy.toml) 的 `minVersion` |
| 自定义规则 | 7 条 | 同上 |
| 评估集用例 | 34 条 | [testdata/eval.json](../internal/detector/testdata/eval.json) |
| 质量门槛 | precision ≥ 0.95、recall ≥ 0.95 | [eval_test.go](../internal/detector/eval_test.go) |

**基线必须和上面三个数一致**。升级后如果变了，更新这张表。

### 1.2 检查有没有新版本

```sh
cd <repo>
go list -m -versions github.com/betterleaks/betterleaks/v2
```

看是否有高于当前基线的版本。`rc` 版本频繁发布，**不必每个 rc 都升**；判断标准是 release notes 里有没有：

- 新增规则（尤其覆盖 API key / token / 私钥 / 连接串的）
- 规则的 `filter` 或 `regex` 变更（会影响召回或误报）
- `config` / `scan` 包的 API 变更（会影响我们的集成代码）
- `decode`（base64/hex/percent 解码深度）相关变更

### 1.3 升级流程

**先在一个干净的环境里验证，不要直接改仓库。**

```sh
# 1. 记录当前基线
cd <repo> && ./keycordon scan internal/detector/testdata/eval.json > /tmp/before.txt 2>/tmp/before.err || true

# 2. 升级
go get github.com/betterleaks/betterleaks/v2@<new-version>
go mod tidy

# 3. 同步规则文件里的 minVersion
#    proxy.toml 顶部 minVersion 必须 >= 新版本，否则启动时 betterleaks 会拒绝加载

# 4. 跑全部测试
go test ./... 2>&1 | tee /tmp/after.log

# 5. 重点看这三个测试
go test ./internal/detector -run 'EmbeddedRuleTests|EvalCorpus' -v
go test ./internal/detector -bench BenchmarkScan100KB -benchtime 100x
```

**必须全绿的三个门槛**：

1. `TestEmbeddedRuleTests` —— 我们 7 条自定义规则的行为没变（新版本可能改了 `filter` 表达式支持的函数）。
2. `TestEvalCorpus` —— precision / recall 仍在 0.95 以上。
3. 扫描吞吐不低于基线的 80%（新版本可能引入更重的正则）。

**如果评估集挂了**：

- 是**新版本改了规则** → 在 `testdata/eval.json` 里把对应用例的实际行为记下来，判断这算变好还是变坏。变好就更新期望值；变坏就考虑把那条默认规则加进 `disabledRules`。
- 是**我们的自定义规则**失效 → 通常是 filter 函数被改名/删除。查 betterleaks 的 `scan/expr.go` 支持的函数列表，改 `proxy.toml`。
- 都修不了 → **回滚到旧版本**，在 §5 的记录表里写清原因，下次再试。**绝不带着失败的评估集发布。**

### 1.4 值得关注的上游改动

每次升级后，扫一眼这些文件的 diff：

| 文件 | 看什么 |
|---|---|
| `config/betterleaks.toml` | 新增/删除的规则 ID，尤其是 `generic-*`、`*-key`、`*-token` |
| `scan/scanner.go` | 扫描流程、去重/抑制逻辑（`isSuppressedByHigherSpecificityFinding`） |
| `scan/expr.go` | filter 表达式可用的函数与变量 |
| `sources/` | Fragment 结构与 Attributes 传递方式（我们的叶子 ID 靠它） |
| `report/` | `Finding.Location` 的行列语义（我们靠它换算字节偏移） |

`report.Location` 或 `sources.Fragment` 的语义一旦变，`internal/detector/detector.go` 的 `locate()` / `locationRange()` 就要跟着改，并有专门的测试（`TestScanOffsets`、`TestScanEncoded`）守着。

### 1.5 升级时顺手做的事

- 把新增的 key 格式加进评估集的 `want`。
- 如果新版本新增了 API key 前缀（如新的 `sk-xxx-` 格式），考虑加进 `internal/vault/kind.go` 的 `kindPrefixes`，让占位符类型更有语义。
- 重跑一次真实上游的联调（小米 MiMo 或你手边的任何上游），确认端到端仍然正常。

---

## 2. AI 端点

### 2.1 当前基线

| 项 | 值 |
|---|---|
| 登记的适配器 | 26 个（不含 3 个抽象基类） |
| 定义位置 | [internal/protocol/protocols/](../internal/protocol/protocols/) |
| 端点全表 | [design.md 附录 B](design.md) |
| 路由测试 | [registry_test.go](../internal/protocol/registry_test.go) |

### 2.2 权威来源（按可信度排序）

1. **CLIProxyAPI 的路由表** `internal/api/server_routes.go`。这是最直接的来源——CPA 暴露什么，我们就要覆盖什么，因为用户几乎都把 keycordon 放在 CPA 前面。
2. **上游厂商的 API 文档**。OpenAI / Anthropic / Google 的 changelog，以及各家兼容服务（DeepSeek、智谱、Moonshot、Qwen、MiMo、xAI…）。
3. **agent 客户端的实际请求**。Claude Code、Codex CLI、Gemini CLI 发版时常带新端点。
4. **同类项目的端点清单**（见第 3 节）。

### 2.3 检查流程

```sh
# 1. 拉最新的 CPA 路由表
cd /tmp && rm -rf cpa-src
git clone --depth 1 https://github.com/router-for-me/CLIProxyAPI cpa-src
grep -nE 'v1\.(POST|GET|PUT|DELETE)|v1beta\.|codexDirect\.|engine\.(GET|POST)' \
  cpa-src/internal/api/server_routes.go

# 2. 把它和我们登记的路径逐条比对
keycordon adapters            # 打印已加载的适配器

# 3. 用真实路径做一次匹配验证（不启动代理）
cat > /tmp/probe_test.go <<'EOF'
package protocol
import "testing"
func TestProbe(t *testing.T) {
    r, _ := Load(Options{})
    for _, p := range []string{ /* 新端点列表 */ } {
        a := r.Match("POST", p, false)
        id := "(passthrough!)"
        if a != nil { id = a.ID + "/" + a.Filter }
        t.Logf("%-50s -> %s", p, id)
    }
}
EOF
cp /tmp/probe_test.go internal/protocol/zz_probe_test.go
go test ./internal/protocol -run Probe -v
rm internal/protocol/zz_probe_test.go
```

**判定标准表**：

| 输出 | 含义 | 处理 |
|---|---|---|
| `(passthrough!)` | 没登记，请求原样透传 | **必须处理**：要么加适配器，要么明确决定不支持 |
| `xxx/on` | 已过滤 | 检查字段列表对不对 |
| `xxx/unsupported` | 明确拒绝（WS、Realtime） | 确认这是有意为之 |

### 2.4 新增适配器

适配器是声明式的，**不改 Go 代码**。步骤：

1. 在 [protocols/](../internal/protocol/protocols/) 找最接近的现有文件，复制一段。
2. 决定 `scan` 模式：
   - `all_strings`（继承 `_common`）：完整对话协议，有 system/messages 历史。适用于 chat / responses / messages / gemini。
   - `fields`（继承 `_prompt_only`）：用户内容集中在少数 prompt 类字段，且不进下一轮上下文。适用于 image / audio / video / rerank / 判定类。
3. 只对**确实不进上下文**的字段用 `fields`；拿不准就用 `all_strings` 加 `frozen`。
4. 在 [registry_test.go](../internal/protocol/registry_test.go) 的测试表里加一行。
5. 如果该端点有 `stream`，在 [rewrite_test.go](../internal/rewrite/rewrite_test.go) 加一个「密钥被替换、响应被还原」的用例。
6. 更新 design.md 附录 B 的端点表。
7. 更新本文 §2.1 的适配器数量。

**判断「要不要做」**：

- 用户内容会进入下一轮上下文（chat / 工具结果） → **必须做**。
- 用户内容是一次性的 prompt（生图、TTS、搜索查询） → **必须做**，成本很低。
- 只有元数据、没有用户文本（`/v1/models`、`GET /v1/videos/:id`） → 不做，透传。
- 二进制流或 WebSocket → 明确返回 501 / 426，**不要静默透传**。

### 2.5 换上游时的额外检查

新上游可能带来：

1. **新的认证头**。查 `internal/proxy/filter.go` 的 `credential()`，补上新的头名或查询参数，否则所有客户端会被认成同一个调用方（vault 混在一起，虽然不会泄露，但会让缓存串味）。
2. **新的 SSE 事件格式**。如果是已有协议的扩展（如 `reasoning_content`），用 `all_strings` 的默认处理即可；如果是全新的事件类型，在适配器的 `response.deltas` 里加。
3. **新的压缩方式**。`internal/proxy/decode.go` 只支持 gzip / deflate / br / zstd。遇到别的（`compress`、`lz4`）应返回 415 而不是放行。
4. **新的流式格式**。JSON 数组（Gemini 无 `alt=sse`）、NDJSON（Ollama）已支持；如果是别的分帧方式，需要新增 `restore.Stream` 实现。

---

## 3. magpie 等同类实现的变更

### 3.1 当前基线

| 项 | 值 |
|---|---|
| 上次审查 | 2026-11-23，commit `41ff2dd` |
| 审查结论 | [magpie-review.md](magpie-review.md) |
| 已借鉴并实现 | 5 项（见该文档第 6 节） |
| 明确不做 | 直接引入代码、钱包/助记词规则 |

### 3.2 检查流程

```sh
cd /tmp && rm -rf m2
git clone --depth 1 https://github.com/yetone/magpie m2
cd m2
git log --oneline -30 -- internal/redact internal/masking internal/gateway
```

**只看这几个目录**：

| 目录 | 看什么 |
|---|---|
| `internal/redact/` | 规则表、否决函数（`fieldvalue.go`）、`known.go`、`shape.go`、`json.go` 的 `kept` 键表 |
| `internal/gateway/masked*.go`、`redact*.go` | 与网关的接线、缓存前缀测试（那些注释里全是用户报告的 bug） |
| `internal/redact/*_test.go` | 尤其是 `eval_cases_test.go`——新用例就是新发现的真实误报 |
| `docs/reference.md` | 搜 "Privacy"、"masking"、"redact" |

**最高效的一步**：直接读**注释**。magpie 的代码注释里写满了「哪一次用户报告促成了这个改动」，例如：

- `fieldvalue.go` 开头列了 7 类误报（路径、代码标识符、版本号、时间戳…）
- `known.go` 开头解释了缓存前缀被打穿的完整场景
- `json.go` 的 `kept` 注释解释了 Codex 的 `namespace` 校验

这些是免费的实战情报。**每次审查至少把那几个文件的注释通读一遍**。

### 3.3 同类项目清单

除 magpie 外，这些也值得偶尔看一眼：

| 项目 | 关系 |
|---|---|
| [yetone/magpie](https://github.com/yetone/magpie) | 主要参考，隐私过滤 + 网关 |
| [Moraxyc/cpa-reductant](https://github.com/Moraxyc/cpa-reductant) | CPA 插件，用 magpie 的 `internal/redact`，端点清单值得对照 |
| [amwangfan/privacy-gateway](https://github.com/amwangfan/privacy-gateway) | 早期调研对象，曾被发现有跨租户泄露、gzip 绕过等 bug |
| betterleaks 的 issue / PR | 规则漏检的第一手来源 |

**看同类项目时的固定问题**：

1. 它支持的端点我们有没有？（用 §2.3 的探针验证）
2. 它记录的误报我们有没有？（逐条加到评估集，先看是 `want` 还是 `keep`）
3. 它的占位符/还原设计有没有比我们更稳的地方？
4. 它有没有已知的**安全缺陷**？（跨租户、编码绕过、fail-open 放行）

### 3.4 借鉴的判定

| 情况 | 做法 |
|---|---|
| 我们确实有同一个 bug | 立刻修，补测试，写进 design.md |
| 我们设计上已经避免了 | 在 [magpie-review.md](magpie-review.md) 里记一句「对方遇到过、我们不需要」（防止以后有人来问） |
| 是取舍差异（如他们做个人信息，我们只做密钥） | 记录，不实现 |
| 需要引入代码 | 默认**不引入**。理由见 magpie-review.md 第 4 节（`internal/` 限制、体量、模型耦合、引擎不一致） |

**借鉴时的硬规矩**：只借鉴**思路**，自己写实现。原因有两个——许可证上干净，以及我们必须用 betterleaks，不能混两套规则引擎。

---

## 4. 编码与引用第三方检查

（暂不需要，记录在此以防将来考虑。）

如果将来想：
- 引入新的检测引擎（例如自研规则）
- 引入本地小模型（privacy-filter、AstrLink Guard）
- 引入 PII 检测（邮箱、电话、身份证）

先回答三个问题：

1. 它带来的是**召回**还是**精度**？如果只是精度，先看 §1 的评估集能不能用规则解决。
2. 它的失败模式是什么？能不能 fail-open？（响应侧可以，请求侧不行。）
3. 它会不会让占位符不再确定？（一旦不确定，前缀缓存全废，这是最贵的代价。）

---

## 5. 审查记录

每次审查在下面追加一行。**必须写**：日期、betterleaks 版本（前后）、适配器数量（前后）、magpie commit、结论。

| 日期 | betterleaks | 适配器 | magpie commit | 本次结论 |
|---|---|---|---|---|
| 2026-11-23 | `v2.0.0-rc.9` | 24 | `41ff2dd` | 初次审查；借鉴 5 项并实现；新增 `veto`、`sent` 缓存、评估集 |
| 2026-11-24 | `v2.0.0-rc.9` | 26 | `41ff2dd` | 对照 cpa-reductant + CPA 路由表；补 `xai-tts`、`codex-alpha-search`、Realtime 全匹配、`/v1/tunnel` |

**记录模板**：

```markdown
| YYYY-MM-DD | `<旧>` → `<新>` | `<旧>` → `<新>` | `<commit>` | 一句话结论 |
```

如果本次**没有**升级、**没有**新增适配器，也要记一行，写「无变化，已核对」。

---

## 6. 每次审查后必须仍然成立的断言

这些是项目的核心不变量。**任何一次审查后都要重新确认**——`./scripts/maintenance.sh` 会自动跑完下表全部测试：

```sh
cd <repo>
./scripts/maintenance.sh
# 等同于：
go build ./... && go vet ./... && gofmt -l . && go test -race -count=1 ./...
```

| 断言 | 由谁保证 |
|---|---|
| 未登记端点的请求字节完全不变 | `TestPassthroughUntouched` |
| 无密钥的已登记请求字节完全不变 | `TestNoSecretIsByteIdentical` |
| 占位符跨重启稳定 | `TestDeterministicAcrossRestarts`、`TestPlaceholderDeterministic` |
| 迟到的已知值不重写历史 | `TestLateKnownValueDoesNotRewriteHistory` |
| 调用方之间不能互相还原 | `TestRestoreIsolation`、`TestCallerIsolation` |
| 流式还原不改变事件条数 | `TestSSEChatSplitEverywhere` |
| 代码/路径/版本不误报 | `TestVetoedValuesGoAsWritten`、`TestEvalCorpus` |
| 检测质量 ≥ 0.95 / 0.95 | `TestEvalCorpus` |
| 扫描吞吐 ≥ 100 MB/s（无密钥）/ 25 MB/s（1000 个密钥） | `BenchmarkScan100KB`、`SCALE=1 go test ./internal/rewrite -run TestScaleTable` |
| TTFT 增量 ≤ 20 ms（典型请求）/ ≤ 100 ms（1M token、1000 密钥） | 见 design.md §11.2，改动热路径后重测 |
| 请求之间不串行 | `TestConcurrentRequests`、`TestConcurrentStreams`（见 design.md §11.3） |
| 重复的历史几乎不耗时 | `TestRepeatedHistoryIsCheap`（见 design.md §7.8） |
| 镜像可构建且能启动 | CI 的 `docker-build` 冒烟测试（`version` + `adapters`） |
| 镜像以非 root 运行、密钥落在卷上 | 手工：`podman run --rm -v kcd:/var/lib/keycordon ...` 后检查 `/var/lib/keycordon/master.key` 属主 |

**如果某条断言需要修改才能通过，那就是一次设计变更**——必须先更新 [design.md](design.md) 说明原因，再改测试。

---

## 7. 快速命令参考

```sh
# 隔离环境（本机零污染）。把下面这段存成自己的 env 文件，每次 go 命令前 source。
# GOROOT/GOPATH/GOMODCACHE/GOCACHE/GOENV/XDG_* 全部指向 /tmp，不碰 ~/.cache 与 ~/.config。
export GOROOT=/tmp/goroot PATH=/tmp/goroot/bin:$PATH
export GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache GOCACHE=/tmp/gocache
export GOENV=/tmp/goenv/env GOTELEMETRY=off GOTOOLCHAIN=local
export XDG_CONFIG_HOME=/tmp/goxdg/config XDG_CACHE_HOME=/tmp/goxdg/cache
# 官方代理；国内环境换成 goproxy.cn / sum.golang.google.cn
export GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org GOFLAGS=-mod=mod
```

> 如果 `/tmp/keycordon-env.sh` 还在，`source` 它即可，内容与上面相同。走代理的网络配置也放在里面。

```sh
# 一键审查
./scripts/maintenance.sh

# 全部验证
go build ./... && go vet ./... && gofmt -l . && go test -race -count=1 ./...

# 检测质量
go test ./internal/detector -run 'EmbeddedRuleTests|EvalCorpus' -v

# 性能
go test ./internal/detector -bench BenchmarkScan100KB -benchtime 100x
go test ./internal/rewrite -bench BenchmarkChat64KB -benchtime 50x

# 适配器清单
go run ./cmd/keycordon adapters

# 单条文本的判定（会走 veto，与代理行为一致）
echo 'the password is pa55word-9x' | go run ./cmd/keycordon scan

# 上游依赖
go list -m -versions github.com/betterleaks/betterleaks/v2
go list -m -u all
```

**离线扫描备注**：`keycordon scan` 与代理走同一条判定链（detector + veto），但**不做** `sent` 形态冻结（那条路径需要调用方 ID 和上游标识）。用来查「某段文本会不会被替换」是准确的；用来复现「历史是否被重写」不适用。
