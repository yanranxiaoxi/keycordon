# keycordon

keycordon 是一个面向 LLM API 的轻量反向代理。请求离开本机前，它把请求体中的 API key、令牌、私钥、连接串密码等密钥替换成占位符（例如 `<SECRET_GITHUB_TOKEN_76fff9b6>`）。响应返回客户端前，它再把占位符还原成原值，SSE 流式响应也支持。上游模型始终看不到原始密钥，客户端和 agent 工具照常拿到可执行的结果。

- **检测**：以 Go 库的形式引用 [betterleaks](https://github.com/betterleaks/betterleaks) v2，不复制其代码。在默认规则之外，补充了针对环境变量赋值、无用户名连接串和**无前缀随机串**（结合熵、token 比率和结构白名单判定）的自定义规则。
- **影响面小**：只处理已登记的 AI 端点（OpenAI Chat / Responses / Codex、Anthropic Messages、Gemini / Vertex / Gemini CLI、Ollama，以及 embeddings、images、audio、moderations、rerank、LiteLLM decisions / systemone 等），其他请求一律原样透传。
- **不破坏前缀缓存**：只按字节区间改写命中的字符串，其余字节保持不变。占位符由主密钥、调用方和密钥值做 HMAC 确定性生成，重启后不变。占位符说明固定追加在 system 末尾。
- **只用内存**：映射只存在内存里，重启即丢弃。唯一落盘的是主密钥（`0600`），它不能解出任何密钥。
- **调用方隔离**：按客户端凭据（`Authorization`、`x-api-key`、`x-goog-api-key`、`?key=`、`?auth_token=`）划分 vault，A 的占位符不能被 B 还原。

完整设计与边缘情况分析见 [docs/design.md](docs/design.md)；与同类工具 magpie 的对照、可借鉴项与已知缺口见 [docs/magpie-review.md](docs/magpie-review.md)。

## 构建

需要 Go 1.26 及以上版本。

```sh
go build -o keycordon ./cmd/keycordon
```

## 使用

把 keycordon 放在 CLIProxyAPI（或任何兼容的上游）前面，客户端的 base URL 改为指向 keycordon：

```sh
keycordon serve -upstream http://127.0.0.1:8317 -listen 127.0.0.1:8318
# 或者
keycordon serve -config keycordon.yaml
```

```text
Claude Code / Codex / SDK  ──►  keycordon :8318  ──►  CLIProxyAPI :8317  ──►  各家模型
```

配置项及默认值见 [keycordon.example.yaml](keycordon.example.yaml)，所有字段都可以省略。

其他命令：

```sh
keycordon scan FILE        # 离线查看某个文件里哪些内容会被替换（结果打印到 stdout，命中统计打印到 stderr）
keycordon adapters         # 列出已加载的协议适配器
keycordon version
```

健康检查：`GET /_keycordon/healthz`，返回版本、规则哈希和主密钥指纹（不是主密钥本身）。

## 行为要点

| 情况 | 处理 |
|---|---|
| 未登记的路径 | `httputil.ReverseProxy` 原样透传，不读 body、不改头 |
| 请求体压缩（gzip / deflate / br / zstd） | 解压后扫描，转发未压缩的 body；未知编码返回 415 |
| JSON 非法、嵌套过深 | 400，不转发 |
| 检测超时或出错 | 503，**绝不转发未扫描的请求**（fail-closed） |
| 响应还原出错 | 原样透传（fail-open，最坏情况是客户端看到占位符） |
| 思考内容 / 签名 | 请求侧冻结、响应侧不还原，避免签名校验失败 |
| WebSocket / Realtime | 默认返回 501，客户端会回退到 HTTP；可配置为透传 |
| 非回环地址监听且请求没有凭据 | 401 |
| `mode: observe` | 只记日志、不改写，用来上线前评估误报 |

### 请求体大小限制

默认 `max_body_bytes: 8 MiB`（收到的原始 body）、`max_decoded_bytes: 16 MiB`（解压后）。超出分别返回 **413**。

这是按「纯文本、2M token 上下文」定的：

| 内容 | 字节/token | 2M token |
|---|---|---|
| JSON / 密集代码 | ~4.8 | 10.9 MiB |
| 英文 | ~4.0 | 7.6 MiB |
| Python / Go | ~3.5 | 7.6 MiB |
| base64 | ~3.0 | 5.7 MiB |
| 中文 | ~1.5 | 2.9 MiB |

所以英文、中文、常规代码的 2M 请求都在 8 MiB 以内。

**什么时候需要调大**（改 `keycordon.yaml` 的 `limits` 段）：

| 症状 | 原因 | 建议 |
|---|---|---|
| 带图请求 413 | 模型按 tile 计价，图片的 body 远大于它的 token 数：一张 4 MiB 的 PNG 是 5.6 MiB 的 body，10 张就是 53 MiB | `max_body_bytes: 64MiB`、`max_decoded_bytes: 128MiB` |
| 纯 JSON / 纯密集代码的 2M 请求 413 | 这种内容每 token 占 4.8 字节，2M 就是约 11 MiB | 16 MiB / 32 MiB |
| 只有压缩请求才 413 | 压缩比高，解压后超了 | 只调 `max_decoded_bytes`，至少是 `max_body_bytes` 的 2 倍 |
| 大响应里仍然看到占位符 | 非流式响应超过 `max_response_bytes` 时不做还原、原样透传 | 调大 `max_response_bytes` |

```yaml
limits:
  max_body_bytes: 67108864      # 64 MiB
  max_decoded_bytes: 134217728  # 128 MiB
  max_response_bytes: 67108864  # 64 MiB
```

**调大之前先算内存**：内存峰值 ≈ `max_decoded_bytes` × 并发数。从 16 MiB 提到 128 MiB 就是 8 倍——100 个并发从 1.6 GiB 变成 12.8 GiB。宁可用容器内存上限约束，也不要把请求串行化（那会让一个慢请求拖住所有人的首字节）。

完整的字节/token 推导见 [docs/design.md](docs/design.md) §11.4。

### 端点覆盖对照

与 [cpa-reductant](https://github.com/Moraxyc/cpa-reductant)（同为 CPA 侧隐私插件）的端点清单逐条核对结果：

| 对方的端点 | keycordon | 备注 |
|---|---|---|
| `/v1/messages`、`/v1/messages/count_tokens` | ✅ `anthropic-messages` | |
| `/v1/chat/completions`、`/v1/completions` | ✅ `openai-chat` / `openai-completions` | |
| `/v1/responses`、`/v1/responses/compact`、`/backend-api/codex/responses` | ✅ `openai-responses` | 另含 Vertex 上的 Claude `rawPredict` |
| `gemini` 的 `:generateContent`、`:streamGenerateContent`、`:countTokens` | ✅ `gemini` | 另含 `:embedContent`、`:batchEmbedContents`、Vertex 路径 |
| `/v1beta/interactions`（`model` 与 `agent` 两种请求） | ✅ `interactions` | 全字段扫描，两种请求都覆盖 |
| `openai-image` / `openai-video` | ✅ `openai-images` / `openai-videos` | |
| `openai-speech` | ✅ `openai-audio-speech` / `openai-audio-transcription` | 另含 `POST /v1/tts`（xAI 自有字段） |
| `codex` / `antigravity` | ✅ | 两者最终都走 `/v1internal:*` 与 `/backend-api/codex/*`；keycordon 的 `gemini-cli`、`openai-responses` 已覆盖。也覆盖 Ollama 原生接口 |

**比对方多覆盖的**：`/v1/embeddings`、`/v1/moderations`、`/v1/rerank`、LiteLLM 的 `/decisions`、`/systemone`、`/extraction`、`/ocr`、`/tokenize`、Anthropic Message Batches、Ollama `/api/chat`、`/api/generate`、Codex 的 `/alpha/search`、Vertex 的 `rawPredict`/`streamRawPredict`。

**刻意不支持（返回 501 / 426，不会静默放行）**：所有 WebSocket 升级（`/v1/responses`、`/v1/realtime*`、`/v1/live`、`/v1/tunnel`、`BidiGenerateContent`）和 Realtime 的 HTTP 控制端点（`/v1/realtime/*`）。对方声称支持 WebSocket 客户端经它转发，但上游仍是 HTTP——keycordon 选择明确拒绝，由客户端回退到 HTTP。

自定义或覆盖协议适配器：在 `~/.config/keycordon/protocols/` 放 YAML 文件，格式与 [internal/protocol/protocols/](internal/protocol/protocols/) 中的内置适配器相同。ID 相同时覆盖内置适配器。

## 实测兼容性

已用真实上游（小米 MiMo，`https://api.xiaomimimo.com/v1` + `mimo-v2.6-flash`）跑通下列场景，输出均为「上游只看到占位符，客户端拿回原文」：

| 场景 | 结果 |
|---|---|
| OpenAI Chat 非流式，三个不同格式的密钥 | 全部替换并还原，响应与上游文本逐字一致 |
| OpenAI Chat SSE，密钥被切成两段跨事件 | 跨事件还原正确，事件条数与上游相同 |
| 工具调用（非流式 / 流式），密钥在 `arguments` | 还原后仍是合法 JSON，`ghp_` 值正确回填 |
| 两轮工具循环，`reasoning_content` 按 MiMo 建议回传 | 思考内容保持占位符不还原（签名/一致性），tool 结果里的明文被重新替换 |
| Anthropic Messages（非流式 + SSE，含 thinking） | 文本还原，thinking 与 signature 不动 |
| 多轮前缀缓存 | 第 2、3 轮 `cached_tokens` 正常增长（1472 / 1536），占位符不破坏前缀 |
| 重启后占位符稳定性 | 同一请求在重启前后发给上游的字节完全相同 |
| 单请求 182 KB、120 轮历史 | 扫描 + 转发正常，全链路 10.7 s（含模型生成） |
| 6 客户端并发（各自独立凭据） | 无跨调用方密钥泄露，无占位符残留，上游收到的请求里 0 个原始 token |
| 中文散文凭据（「数据库密码是 …」「秘钥 …」） | 命中并还原（为此新增了两条规则，见 docs/design.md 4.4） |
| 图像 `data:` URI | 图片数据原样透传，不扫描 |
| `mode: observe` | 上游收到原文，日志记录命中规则，不改写 |

**实测中发现并修复的问题**：

1. 散文里提到的密码原本完全漏检（「数据库密码是 hunter2-but-longer」「the password is pa55word-9x」）。原因和取舍见 [docs/design.md](docs/design.md) 4.4 与实现说明第 11 条。
2. 迟到的已知值会重写已发送的历史，把前缀缓存打穿（上游早已见过明文，改写没有安全收益）。机制见 [docs/design.md](docs/design.md) §7.8。
3. 规则靠上下文命中时也会命中代码、路径、版本号和过期时间（`PRIVATE_KEY_PATH=~/.ssh/id_ed25519`、`access_token = get_access_token_v2`、`jsonwebtoken = "9.2.0-beta1"` 等）。现在由 `internal/veto` 否决，见 [docs/design.md](docs/design.md) §4.3.1。

## 检测质量

`internal/detector/testdata/eval.json` 是回归评估集：每条用例是一个 agent 会发出的文本，带「必须替换」和「必须原样保留」两组值。当前 33 条用例，precision 1.000 / recall 1.000，CI 门槛均为 0.95。新增规则或调整 filter 时先加用例。

与同类工具 magpie 的对照、可借鉴项与取舍见 [docs/magpie-review.md](docs/magpie-review.md)。

## 开发

```sh
go test ./...
go test -race ./...
./scripts/maintenance.sh          # 一键跑完维护清单的全部检查
```

## 容器

镜像约 24 MB，单静态二进制，以非 root（uid 10001）运行：

```sh
docker build -t keycordon:latest .
docker run -d -p 8318:8318 -v kcdata:/var/lib/keycordon \
  --add-host host.docker.internal:host-gateway \
  keycordon:latest serve -config /etc/keycordon/config.yaml \
    -upstream http://host.docker.internal:8317
```

主密钥、上游地址、调用方隔离、健康检查与升级注意事项见 [docker/README.md](docker/README.md)。用 Podman Quadlet（systemd 托管、开机自启、自动更新）部署见 [docs/quadlet.md](docs/quadlet.md)。

```sh
cp deploy/quadlet/keycordon.container ~/.config/containers/systemd/
systemctl --user daemon-reload && systemctl --user start keycordon
```

CI（`.gitlab-ci.yml`）：

| 触发 | 镜像 | 二进制（软件包仓库） |
|---|---|---|
| 默认分支 push | `nightly` + `sha-<短哈希>`（仅 Docker Hub） | 7 个平台，目录 `nightly`，文件名带 `0.0.0-<短哈希>` |
| `vX.Y.Z` 标签 | `<版本>` + `<次版本>` + `latest`（两个仓库） | 7 个平台，目录 `<版本>`，固定 |

`latest` 指向最新发布版本，`nightly` 指向默认分支最新的 git 构建。二进制支持 linux/amd64、linux/arm64、darwin/amd64、darwin/arm64、windows/amd64、windows/386、windows/arm64，校验和由 GitLab / GitHub 在页面自动提供。详见 [docker/README.md](docker/README.md)。

## 维护

这个项目有三个会持续变化的外部依赖面：betterleaks 的版本、AI 端点清单、同类实现（magpie 等）的变更。任何一项落后都会导致「以为保护了、其实没有」。

定期审查的完整操作手册见 [docs/maintenance.md](docs/maintenance.md)：节奏与触发条件、每一步的命令、判定标准、审查记录表、以及每次都必须重新确认的核心不变量。

```sh
./scripts/maintenance.sh   # 自动核对版本基线、跑全部断言、打印当前状态
```
