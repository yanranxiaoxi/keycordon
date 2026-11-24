# magpie 借鉴评估

对 [yetone/magpie](https://github.com/yetone/magpie) 的隐私过滤实现做了一次通读（2026-11-23，commit `41ff2dd`），评估 keycordon 可以从它那里借鉴什么、能否直接引入。

## 1. magpie 的隐私过滤是什么

magpie 是一个「本地网关 + 菜单栏 App」，把多个 agent（Claude Code、Codex、Gemini CLI…）和多家的模型/账号统一到 `127.0.0.1` 的一个网关后面。它的隐私过滤是网关的一个内置插件 `redact`（Settings → Privacy 打开，默认关闭），作用范围与 keycordon 高度重合：请求出去前把密钥/个人信息换成占位符，响应回来时换回原值，流式也支持。

代码分布：

| 位置 | 内容 | 规模 |
|---|---|---|
| [`internal/redact/`](https://github.com/yetone/magpie/tree/main/internal/redact) | 规则引擎、占位符、还原、擦除、脱敏评估 | 约 8200 行生产代码 + 大量测试 |
| [`internal/masking/`](https://github.com/yetone/magpie/tree/main/internal/masking) | 网关中间件的 masker 适配层 | 约 1200 行 |
| [`internal/maskrec/`](https://github.com/yetone/magpie/tree/main/internal/maskrec) | 每次请求的「脱敏记录」（Kinds/By/计数） | 约 1700 行 |
| [`internal/pii/`](https://github.com/yetone/magpie/tree/main/internal/pii) | 本地小模型（Privacy Filter / AstrLink Guard）的推理封装 | 约 7300 行 |
| [`internal/gateway/`](https://github.com/yetone/magpie/tree/main/internal/gateway) | 与网关的接线、SSE、缓存前缀测试 | 大量 `*_redact_test.go` / `masked_*_test.go` |
| `native/privacy-filter/` | 上述本地模型的 C++ 实现（Vulkan） | — |

关键事实：**它没有可被外部导入的公开包**。`internal/redact` 在 `internal/` 下，Go 的 internal 规则使外部模块无法 import；模块路径是 `github.com/yetone/magpie`，唯一的入口是 `main.go`（可执行程序）。

## 2. 与 keycordon 的设计对比

| 维度 | keycordon | magpie |
|---|---|---|
| 形态 | 独立反向代理，只管 AI 端点 | App 内置网关，兼做 provider 路由/账号切换 |
| 检测引擎 | betterleaks v2（476 条默认规则）+ 7 条自定义规则 | 自研规则表（约 120 条）+ 可选本地小模型 |
| 覆盖范围 | 只脱敏密钥/凭据 | 密钥 + 个人信息（邮箱、电话、身份证、银行卡、IBAN、生日、MAC、地址、用户名、主机名、桶名）+ 用户自定义词 |
| 占位符 | `<SECRET_TYPE_hex8>` | `{{KIND_base32_8}}` |
| 占位符密钥 | HKDF(master, caller) → 每调用方独立 | 全局单密钥，**不按调用方分区** |
| 稳定性的关键 | 内容 + 调用方 + 主密钥决定 | 内容 + 主密钥决定 |
| 前缀缓存 | 有完整设计（§7），但存在下述缺口 | `sentSpans`/`allowKept` 显式解决「迟到已知值」 |
| 本地模型 | 明确不要 | 可选，默认关 |
| 持久化 | 只存主密钥 | 只存占位符密钥 |
| 语言/依赖 | Go，仅 3 个外部依赖 | Go，依赖较多 |

## 3. 可以借鉴的地方（按价值排序）

### 3.1 迟到已知值不得重写已发送的历史 —— 高价值，已实现

这是本次评估中**唯一发现的、keycordon 现存的真实缺陷**。

场景：
1. 第 1 轮，用户发「the value is `Sup3rS3cretPw9x` remember it」。这个值没有可识别的上下文，keycordon 不替换，原文发给上游。
2. 第 2 轮，历史里带上第 1 轮，新消息里出现「the password is `Sup3rS3cretPw9x`」。这次命中了规则，值进入 vault。
3. 第 3 轮，`known` 回扫在第 1 轮的历史里也发现了它，于是把**已经以明文发出去的那段历史**改写成了占位符。

结果：第 1 轮那段字节变了，从那里往后的所有缓存全部失效。上游已经见过明文，这时再替换它**没有任何安全收益**，只是白付一次全量重算的钱。

我写了一个三轮回放复现了这一点（turn 3 前缀被破坏）。

magpie 的做法（`internal/redact/known.go` 的 `sentSpans` + `internal/redact/allowkept.go`）：

- 记住「这段文本在某条路由上第一次是以什么形态发出去的」，键是 `hash(route, text, 覆盖选项)`，记的是**命中的区间**，不是值本身。
- 再次发送同一段文本时，**沿用它第一次的形态**：第一次发了明文，以后还是明文；第一次替换了，以后还是同一个占位符。
- 从没发过的**新文本**才用当前规则重新判定。
- 换了 `Route`（换了 provider/模型）就重新判定，因为那段明文没发到那个上游。

对 keycordon 的落地方式：

- 我们已经有 `Rewrite` 结果里的 `Replaced`，可以在 vault 里再加一层 `map[textHash][]span`（按调用方分区 + 按上游标识分区）。
- 文本很短（< 64 字节）时不记，代价大于收益。
- 只需要在已知值回扫（`Caller.FindKnown`）的路径上生效；规则命中是稳定的，本来就每轮一致。
- 缓存上限、LRU 淘汰，被淘汰退化成「按当前规则判定」，最坏是打一次缓存，与现在的行为相同。

这一条我建议**优先做**，因为它是成本问题而非功能问题，而前缀缓存正是这个项目最在意的指标。

### 3.2 规则级误报过滤：代码/路径/版本文本域 —— 中高价值，已实现

我把 magpie 注释里点名过的用户误报逐条拿来测 keycordon，结果如下（`[OK]` 表示没有误报）：

| 输入 | keycordon 现状 | magpie 的处理 |
|---|---|---|
| `PRIVATE_KEY_PATH=~/.ssh/id_ed25519` | ❌ 被替换 | 路径值，放过 |
| `credentials: /Users/alice/legacy_credentials/x7k2/adc.json` | OK | 路径值，放过 |
| `access_token = get_access_token_v2` | ❌ 被替换 | 代码标识符，放过 |
| `secret: env.SECRET_V2` | ❌ 被替换 | 代码标识符，放过 |
| `jsonwebtoken = "9.2.0-beta1"` | ❌ 被替换 | 版本号，放过 |
| `tokenizer = "2.4.0-beta02"` | ❌ 被替换 | 版本号，放过 |
| `UI_PASSWORD= UI_ADDR=127.0.0.1:39117 ./svc` | ❌ 把下一个字段当成值 | 空值识别，跳到下一个字段 |
| `internal/auth/token.go:L643-669` | OK | 行号引用，放过 |
| `"access_token_expires_at": "2026-08-30T11:44:31Z"` | OK | 时间戳，放过 |

这些函数都在 `internal/redact/fieldvalue.go`，逻辑独立、**不依赖 magpie 的任何其他部分**，只有 200 行左右：

- `pathValue(v)`：`~/`、`./`、`../` 开头，或 `/home/`、`/Users/` 等根目录开头的路径。
- `versionValue(v)`：`^[~^]?\d+(\.\d+)+(-beta.1|...)` 形式的版本号。
- `timestampValue(v)`：RFC3339 时间戳。
- `lineRef(v)`：`L643-669` 形式的行号。
- `namesASecret(v)`：**由 2 个以上单词组成、且含 secret/token/password 词根的小写标识符**——这正是 `get_access_token_v2` 和 `os.environ` 的正确判据。
- `nextField(s,a,b)`：`X=` 后面跟空格再跟另一个 `Y=` 时，认作空值。

这些我已经按「引用思路、自己写」的方式记下来了，实现进 keycordon 的 `rewrite` 包（在 `detector` 命中之后、`Placeholder` 之前做一次否决）即可，不引入任何 magpie 代码。

> 注意：这一步会**降低**召回（`PRIVATE_KEY_PATH` 这类确实偶尔有权重），但 magpie 的取舍是「路径和代码标识符泄露的不是密钥」，与 keycordon 的目标一致。

### 3.3 中文/日文/韩文的凭据标签 —— 高价值，已实现

magpie 的 `cjkPasswordNames` / `cjkKeyNames` 词表比我的两条规则宽得多：

```text
密码 密碼 口令 PIN码 安全码 パスワード 暗証番号 비밀번호 암호 비번
密钥 密鑰 秘钥 秘鑰 私钥 私鑰 金钥 金鑰 令牌 权杖 權杖 授权码 授權碼
秘密鍵 トークン シークレット APIキー アクセスキー 토큰 비밀키 API 키 API키
```

**已实现**：`nl-credential-mention-cjk` 的标签表已扩到上面全部词条（含日文、韩文、繁体），并补了 `安全码`、`授权码`、`私钥` 等。

另外它有一处细节值得抄思路：中文标签后面允许**任意 4 字符以上**的值（`密码：786kih` 会被替换），理由是「代码里不会有人把变量叫『密码』」，误报率天然很低。**已按此实现**：CJK 规则的 filter 现在只拒绝非可打印 ASCII、长度 < 4、纯数字、邮箱和少量 schema 关键字，纯字母的值会被替换。英文规则仍保留严格限制（见 6.2）。

### 3.4 `kept` 键清单的细化 —— 中价值，已实现

magpie 的 `kept` 集合比我的一处更细，值得对照补：

- 它把 `reasoning_effort`、`effort`、`stop_reason`、`finish_reason`、`event` 也列进保留键。
- `isID(key)`：`_id` / `_ids` / `Id` / `Ids` 后缀一律保留（我目前靠 `**.id` 之类的显式路径，容易漏）。
- 一个重要的**反向**约束：工具调用 `arguments` 里的 `signature`/`name`/`user_id` 是 agent 自己写的，**不能**按 vendor 的保留规则跳过；只有 `data:` 值跳过。它的 `keepIn(path, key, s, args, defs)` 就是干这个的——我当前的 `payload` 选择器思路一致，但实现上我是「payload 里忽略冻结」，它是「args 里只跳过 data URI，defs 里只扫 description」，后者更精确。
- Codex 会校验 `namespace` 满足 `^[a-zA-Z0-9_-]+$`，遮蔽其中单词会 400。这条我已经通过 `payload` 覆盖，但 `namespace`/`server_label`/`server_name` 不在我的公共冻结表里，建议补。

### 3.5 还原侧的边界判断 —— 中价值

- `standsAlone(kind, s, a, b)`：按 kind 分别判断占位符两侧的字符是否构成「更长的词」。例如邮箱不能紧邻 `._%+-`，IP 不能是 `1.2.3.4.5` 的一段。我的还原目前只认完整 `<...>`，风险较低，但「模型把占位符写在句子中间」时确实可能误替换相邻字符。
- `wholeAddr`：`public-ip-xxxxxxxx` 这类「形似真实值」的替身只在完整出现时还原。keycordon 的占位符带尖括号，天然不会嵌在别的词里，价值不大。
- `restore(s, escaped)` 的 `escaped` 参数区分「还原进 JSON 字符串」与「还原进纯文本」——我已经按 `looksLikeJSON` 自动判断，等价。

### 3.6 钱包私钥 / 种子短语 —— 低价值（可选）

magpie 有一整套加密钱包规则（WIF、BIP32、Solana、Sui、Aptos、Stellar、Nostr、age、Zcash、BIP39 助记词），并用校验和（base58check、CRC16、ed25519 派生）避免把哈希误判成私钥。

keycordon 依赖 betterleaks 的默认规则，覆盖了一部分（`.pem` 私钥头、部分钱包格式）。如果目标用户里有做 Web3 的，这块可以补；否则优先度低于前几项。**注意**：它的「先校验再判定」思路很值得学——`0x + 64 hex` 只有在 `PRIVATE_KEY`、`signer`、`deployer` 等提示词附近才认，因为同一个形状也可能是 tx hash。这与我们 `bare-random-token` 的结构白名单是同一类思路，可以互相印证。

### 3.7 规则内测试 + 评估集 —— 高价值（方法论），已实现

magpie 有一个 135 正例 / 94 反例之类的离线评估集（`eval_cases_test.go` + `testdata/eval-*.json`），每条用例标注「必须被替换」和「必须原样保留」的值，并且**按 three ways 分别打分**（仅规则 / 仅模型 / 两者）。它的用例来源就写明了：「从用户报告的错误遮蔽开始」。

keycordon 目前只有 7 条规则的 `[[rules.tests]]` 和少量 Go 单测。建议直接建一个 `testdata/eval.json`，把上面 3.2 表格里的每一条、以及附录 A 的正反例都录进去，作为 CI 门槛（precision/recall 阈值）。这个**不需要引入任何代码**，纯粹是测试组织方式。

## 4. 能否直接引入

**结论：不能直接 import，也不建议 vendor 进来。**

理由：

1. **`internal/` 限制**。`redact`、`masking`、`pii` 全在 `internal/` 下，Go 编译器禁止外部模块引用。要用只能 fork 整个仓库再改模块路径，等于把 20 万行的 App 拖进一个代理项目。
2. **体量与耦合**。`internal/redact` 8200 行，依赖 `lazyre`（它自己的正则缓存）和 `pii`（本地模型封装、原生二进制下载）。引入它会连带把模型下载、Vulkan 依赖这些完全不需要的东西带进来，与「零依赖、单二进制」的目标冲突。
3. **本地模型**。你已经明确不需要本地模型，而这套代码大量与模型结果交织（`modelSpans`、`sentSpans(sentModel, …)`、`MinScore`、`NamesByModel`）。剥离模型的成本高于重写需要的部分。
4. **检测引擎不一致**。keycordon 用 betterleaks（476 条规则 + 活跃维护），magpie 是自研约 120 条。换成 magpie 的规则等于丢掉 betterleaks 的覆盖面和规则测试体系。
5. **调用方隔离**。magpie 是全局单 vault，keycordon 按调用方分区。这是安全设计上的差异，不是能「合并」的细节。
6. **许可证**。magpie 是 MIT，理论上可以复制代码并保留版权声明。技术上可行，但见上面 1–4，复制的收益远小于自己实现那 200 行。

**真正值得做的**（均已完成，见第 6 节）：

- 借鉴 3.1 的「已发送文本形态固定」机制（自己实现，约 150 行）。
- 借鉴 3.2 的六个否决函数（自己实现，约 200 行），这是收益最高的部分。
- 扩 3.3 的 CJK 词表（纯数据）。
- 借 3.7 的评估集组织方式（纯测试）。
- 补 3.4 的保留键。

## 5. 一个额外发现：magpie 也会打穿缓存

看 `known.go` 的注释，magpie 自己也曾因为这个问题被用户报（Discord 上的 audie：`cache_read` 0、`cache_write` 412K→427K、连续四轮、间隔十秒）。它的修复正是 3.1 那套 `sentSpans`。这说明：

1. 这确实是这类网关最容易踩、也最贵的坑。
2. keycordon 当前缺这一层，不是「设计没写到」，而是「实现时漏了」——`docs/design.md` §7.2 第 7 行只写了「重新替换成同一占位符」，没写「已经以明文发出去的不要回头改写」。

**已修复**：`docs/design.md` §7.2 增加了第 7b 行，§7.8 写了完整机制，`internal/vault/sent.go` 实现，`TestLateKnownValueDoesNotRewriteHistory` 守住。

## 6. 结论与落地情况

| 借鉴项 | 价值 | 状态 | 落地位置 |
|---|---|---|---|
| 3.1 已发送文本形态固定 | **高（省钱）** | ✅ 已实现 | `internal/vault/sent.go`、`internal/rewrite` 的 `spans`、设计文档 §7.8 |
| 3.2 代码/路径/版本否决 | **高（降误报）** | ✅ 已实现 | `internal/veto`、设计文档 §4.3.1 |
| 3.3 CJK 词表扩充 | 中 | ✅ 已实现 | `rules/proxy.toml` 的 `nl-credential-mention-cjk` |
| 3.4 保留键补全 | 中 | ✅ 已实现 | `protocols/00-common.yaml`；`pathpat` 新增 `*suffix` 通配 |
| 3.7 评估集 | 高（防回归） | ✅ 已实现 | `internal/detector/testdata/eval.json` + `eval_test.go`，33 条用例，precision/recall 门槛 0.95 |
| 3.5 还原边界判断 | 低 | 观察 | 占位符带尖括号，风险低 |
| 3.6 钱包/助记词 | 低 | 暂不做 | betterleaks 默认规则已覆盖一部分 |
| 直接引入代码 | — | **不做** | 见第 4 节 |

### 6.1 实现后的实测

评估集 33 条用例（16 个必须命中的值、17 个必须原样保留的值）：

```text
precision 1.000  recall 1.000  (tp=16 fp=0 fn=0)
```

3.2 表格里那 8 条误报全部消失，同时 3.1 的三轮前缀测试通过。

### 6.2 关于「中文标签后允许任意 4 字符以上」

按你的要求实现了：`nl-credential-mention-cjk` 的 filter 现在只拒绝

- 非可打印 ASCII（挡掉「必需的字段」这类中文短语）
- 长度 < 4
- 纯数字
- 邮箱
- 少量 schema 关键字（`password`、`string`、`required` 等）

**纯字母的值现在会被替换**（`数据库密码是 correcthorsebattery` → 命中），这是与英文规则 `nl-credential-mention` 的有意差异：代码里不会有人把变量叫「密码」，所以中文标签的误报率天然低得多。英文规则仍保留「必须含符号或混合大小写+数字」的限制，否则几乎每句含 password 的英文都会误报。

magpie 最值得学的是它**对误报的工程化处理**：每一条规则旁边都写清了「哪一次用户报告促成了它」，并且有离线评估集守住。keycordon 的 `docs/design.md` 附录 A 已经有类似雏形，但还缺一个可执行的回归集。
