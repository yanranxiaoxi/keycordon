# 容器部署

镜像是单二进制的：`keycordon` 静态链接（`CGO_ENABLED=0`），运行层只有 CA 证书和时区数据。镜像大小约 24 MB。

## 构建

```sh
docker build -t keycordon:latest .
# 版本号会打进二进制，`keycordon version` 能看到：
docker build --build-arg VERSION=1.2.3 -t keycordon:1.2.3 .
```

默认使用官方的 `proxy.golang.org` / `sum.golang.org`。**在国内构建**（或 CI runner 在境外但你在国内拉源码）时换镜像：

```sh
docker build \
  --build-arg GOPROXY=https://goproxy.cn,direct \
  --build-arg GOSUMDB=sum.golang.google.cn \
  -t keycordon:latest .
```

`.gitlab-ci.yml` 里的 `GOPROXY` / `GOSUMDB` 是流水线变量，runner 在境外时保持官方值即可；如果 runner 在国内，在 GitLab 的项目变量里覆盖这两个值（见文末「CI 变量」）。

## 运行

keycordon 默认监听 `0.0.0.0:8318`（容器内配置见 [docker/keycordon.yaml](keycordon.yaml)），上游默认 `http://127.0.0.1:8317`——容器里的 `127.0.0.1` 指的是容器自己，**必须改**：

```sh
# 上游是宿主机上的 CLIProxyAPI
docker run -d --name keycordon \
  -p 8318:8318 \
  -v kcdata:/var/lib/keycordon \
  --add-host host.docker.internal:host-gateway \
  keycordon:latest serve \
    -config /etc/keycordon/config.yaml \
    -upstream http://host.docker.internal:8317

# 上游是同一个 compose 网络里的另一个容器
docker run -d --name keycordon \
  -p 8318:8318 -v kcdata:/var/lib/keycordon \
  --network mynet \
  keycordon:latest serve -config /etc/keycordon/config.yaml -upstream http://cpa:8317
```

### docker compose

```yaml
services:
  keycordon:
    image: keycordon:latest
    ports:
      - "127.0.0.1:8318:8318"
    volumes:
      - kcdata:/var/lib/keycordon
    command:
      - serve
      - -config
      - /etc/keycordon/config.yaml
      - -upstream
      - http://cpa:8317
    depends_on:
      - cpa
volumes:
  kcdata:
```

## 主密钥

占位符由 `HKDF(master_key, caller_id)` 派生。**主密钥不变，占位符就不变**，上游的前缀缓存也不会因为容器重启而失效（设计文档 §7.3）。两种保管方式：

**A. 卷（默认）** —— 首次启动生成 `/var/lib/keycordon/master.key`（`0600`，属主 `keycordon`），挂卷即持久：

```sh
docker run -v kcdata:/var/lib/keycordon ...
```

**B. 环境变量** —— 密钥不落盘，适合编排平台注入 Secret：

```sh
docker run -e KEYCORDON_MASTER_KEY=<64位hex或base64的32字节> ...
```

同时在配置里写 `vault.master_key_scope: env`。生成一个：

```sh
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
```

两种方式**不要混用**：环境变量存在时优先级更高，但切换会导致占位符全变、缓存重算一次。

> 主密钥**不是**高敏凭据：它不能解出任何密钥，也不能凭它伪造出 vault 里存在的占位符。详见设计文档 §6.3.1。它仍然不该进镜像、不该进日志——镜像只把它当运行时数据。

## 认证与调用方隔离

容器监听 `0.0.0.0`，所有客户端都从网络进来。配置里 `caller.require_on_non_loopback: true`（默认）意味着：

- 请求带 `Authorization` / `x-api-key` / `x-goog-api-key` / `?key=` / `?auth_token=` → 按凭据划分 vault。
- **不带** 任何凭据 → `401`，而不是所有匿名客户端共用一个 vault。

如果你在容器前面还有一层网关负责认证，且它不再转发客户端的凭据，要么让它转发，要么显式设 `caller.require_on_non_loopback: false`（此时所有人共用一个 vault——功能正常，但缓存会串味，**不建议**）。

## 健康检查

```sh
curl -fsS http://127.0.0.1:8318/_keycordon/healthz
```

返回版本、模式、规则哈希、主密钥指纹、适配器数量。不含任何密钥。路径带 `_keycordon/` 前缀是为了不遮住上游自己的 `/healthz`。

compose 里可以这样接：

```yaml
healthcheck:
  test: ["CMD", "keycordon", "version"]
  interval: 30s
```

（镜像里没有 `curl`；`keycordon version` 只验证二进制可执行，进程活着由编排平台的 `depends_on`/重启策略覆盖。要真探 HTTP，用一个带 `wget` 的 sidecar，或把健康检查交给前面的反向代理。）

## 升级

```sh
docker pull keycordon:latest
docker stop keycordon && docker rm keycordon
docker run -d ... keycordon:latest serve -config /etc/keycordon/config.yaml -upstream ...
```

**只要卷里的主密钥还在，占位符就不变**，升级不会打穿上游缓存。规则集变了可能导致同一段文本的判定变化——这是设计文档 §7.2 #84 记录的已知成本，升级前看一眼 [maintenance.md](maintenance.md) 的检测质量门槛有没有过。

## 自定义协议适配器

内置适配器都在镜像里。要加自己的，挂一个目录并把配置里的 `protocols.extra_dir` 指过去：

```sh
docker run -v "$PWD/my-protocols:/etc/keycordon/protocols:ro" ...
```

配置里写 `protocols.extra_dir: /etc/keycordon/protocols`。文件格式见 [internal/protocol/protocols/](../internal/protocol/protocols/)。

## Quadlet / systemd

用 Podman Quadlet 部署（开机自启、自动更新、journald 日志）见 [docs/quadlet.md](../docs/quadlet.md)，单元文件在 [deploy/quadlet/](../deploy/quadlet/)。

## CI 变量

`.gitlab-ci.yml` 会在默认分支 push 与 `vX.Y.Z` 标签上构建镜像并推送到 Docker Hub 与 GitLab Registry。需要在 GitLab 项目里配置的变量：

### 必填（Settings → CI/CD → Variables）

| 变量 | 说明 | 类型 | Protected | Masked |
|---|---|---|---|---|
| `DOCKERHUB_USER` | Docker Hub 用户名，也作为镜像路径 `docker.io/<user>/keycordon` | Variable | 建议勾 | 否 |
| `DOCKERHUB_PASSWORD` | Docker Hub 的 Access Token（**不是**账号密码；Settings → Security → New Access Token，权限 Read & Write） | Variable | 建议勾 | 是 |

发布后触发 cpa-gate 重建（Settings → CI/CD → Variables）：

| 变量 | 说明 | 类型 | Protected | Masked |
|---|---|---|---|---|
| `CPA_GATE_TRIGGER_TOKEN` | cpa-gate 项目 Settings → CI/CD → Pipeline trigger tokens 生成的令牌。`vX.Y.Z` 发布成功后用它触发 cpa-gate 重建 `latest-keycordon` 镜像 | Variable | 建议勾 | 是 |
| `CPA_GATE_REF` | cpa-gate 的分支名，默认 `main`。必须等于 cpa-gate 的默认分支，否则它的 workflow 规则会直接不建流水线 | Variable | 否 | 否 |

没配 `CPA_GATE_TRIGGER_TOKEN` 时 `notify-cpa-gate` 会失败并说明缺什么，而不是静默跳过：
静默跳过会让人以为 cpa-gate 已经跟着更新了。

`CI_REGISTRY_USER` / `CI_REGISTRY_PASSWORD` / `CI_REGISTRY_IMAGE` 由 GitLab 自动注入，不用配。GitLab 自己的 Container Registry 需要在项目里启用：Settings → General → Visibility → Container Registry。

### 可执行文件（软件包仓库）

默认分支 push 与 `vX.Y.Z` 标签还会把 7 个平台的二进制推到 GitLab 的软件包仓库（generic package），不需要额外配置凭据（用 `CI_JOB_TOKEN`）：

| 平台 | 文件名 |
|---|---|
| linux/amd64 | `keycordon_<版本>_linux_amd64` |
| linux/arm64 | `keycordon_<版本>_linux_arm64` |
| darwin/amd64 | `keycordon_<版本>_darwin_amd64` |
| darwin/arm64 | `keycordon_<版本>_darwin_arm64` |
| windows/amd64 | `keycordon_<版本>_windows_amd64.exe` |
| windows/386 | `keycordon_<版本>_windows_386.exe` |
| windows/arm64 | `keycordon_<版本>_windows_arm64.exe` |

路径规则与 Docker 标签一致：

| 触发 | 目录 | 文件名 | 性质 |
|---|---|---|---|
| 默认分支 push | `nightly` | `keycordon_0.0.0-<短哈希>_linux_amd64` | 固定目录，每次**删除旧包后重传** |
| `vX.Y.Z` 标签 | `X.Y.Z` | `keycordon_X.Y.Z_linux_amd64` | 固定目录，永不覆盖 |

**目录固定、文件名带哈希**是有意的组合：

- **目录固定**（`nightly`）→ 仓库里最多只有「各发布版本 + 一个 nightly」，不会因为每次提交多一个目录而无限膨胀。
- **文件名带哈希**（`0.0.0-a6e19b65`）→ 下载后一眼就能看出是哪次构建、比手上的新不新，不用解开压缩包跑 `keycordon version`。

两者不冲突：包内是覆盖写，所以同一个目录里永远只有一套文件；文件名跟着构建走，所以每次内容都不同。

`keycordon version` 输出的版本与文件名一致：

```sh
$ keycordon version
keycordon 0.0.0-a6e19b65
```

校验和不用自己发：GitLab 在 **Deploy → Package Registry** 的每个文件旁边直接显示 sha256，GitHub Releases 也会自动生成。脚本里想校验就用 API 取：

```sh
curl -sS --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.soraharu.com/api/v4/projects/<项目ID>/packages/<包ID>/package_files" \
  | grep -o '"file_name":"[^"]*"\|"file_sha256":"[^"]*"'
```

下载地址：

```text
${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/keycordon/<目录>/<文件名>
```

例如：

```sh
# 发布版本
curl -fL -o keycordon \
  "https://gitlab.soraharu.com/api/v4/projects/<项目ID>/packages/generic/keycordon/1.2.3/keycordon_1.2.3_linux_amd64"

# nightly：目录固定，文件名要带哈希（先看页面确认，或用 API 列文件）
curl -fL -o keycordon \
  "https://gitlab.soraharu.com/api/v4/projects/<项目ID>/packages/generic/keycordon/nightly/keycordon_0.0.0-a6e19b65_linux_amd64"
```

`nightly` 目录每次构建都会被替换，所以它永远指向默认分支最新一次的构建；文件名里的哈希告诉你具体是哪一次。列当前文件名：

```sh
curl -sS --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.soraharu.com/api/v4/projects/<项目ID>/packages?package_version=nightly" \
  | grep -o '"id":[0-9]*' | cut -d: -f2 | xargs -I{} \
  curl -sS --header "JOB-TOKEN: $CI_JOB_TOKEN" \
    "https://gitlab.soraharu.com/api/v4/projects/<项目ID>/packages/{}/package_files"
```

或者在 GitLab 页面的 **Deploy → Package Registry** 里看，最新一次构建的文件名一目了然，也能直接点下载。

### 镜像标签策略

| 触发 | 产出标签 | 推到 |
|---|---|---|
| 默认分支 push | `sha-<短哈希>`、`nightly` | 仅 Docker Hub |
| `vX.Y.Z` 标签 | `<X.Y.Z>`、`<X.Y>`、`latest` | Docker Hub + GitLab Registry |

- **`nightly`** 始终指向默认分支最新一次构建。它**只能**来自默认分支：脚本会检查 `CI_COMMIT_BRANCH == CI_DEFAULT_BRANCH`，其他分支直接失败，避免手动触发或规则改动让 `nightly` 指向功能分支。
- **`latest`** 始终指向最新的发布版本，与 `nightly` 互不影响。
- GitLab Registry 只留发布版本，不会被每天几十个 nightly 塞满。
- 需要固定某一夜的构建时用 `sha-<短哈希>`，它不可变。
- **两个 job 各自带 `rules`**。`workflow.rules` 只决定「这条流水线跑不跑」，不区分 job；不加 job 级 `rules` 的话，分支流水线里 `docker-release` 会一起跑，然后因为 `CI_COMMIT_TAG` 为空而失败。

### 可选（覆盖流水线默认值）

| 变量 | 默认 | 什么时候改 |
|---|---|---|
| `GOPROXY` | `https://proxy.golang.org,direct` | runner 在国内时改成 `https://goproxy.cn,direct` |
| `GOSUMDB` | `sum.golang.org` | 同上，配合改成 `sum.golang.google.cn` |
| `CONTAINER_IMAGE_NAME` | `keycordon` | 想用别的镜像名时 |

这些都在 `.gitlab-ci.yml` 的 `variables:` 里给了默认值；在 GitLab 项目变量里设同名变量会覆盖它们（项目变量的优先级高于 `.gitlab-ci.yml` 的 `variables:`）。

### Protected 的影响

勾了 Protected 的变量在**非保护分支/非保护标签**上的流水线里不存在。当前 `workflow.rules` 只允许默认分支和 `vX.Y.Z` 标签，所以：默认分支要设为保护分支（一般是默认设置），`v*` 标签也要设为保护标签（Settings → Repository → Protected tags，`v*` + Maintainer）。否则推送会因 `DOCKERHUB_PASSWORD` 为空而 401。

### Docker Hub 仓库

不需要提前创建。首次 `docker push` 会自动创建公开仓库。想要私有仓库，先在 Docker Hub 手工建一个 private 的 `keycordon`。

### 验证配置是否正确

配好之后，推一个标签就能完整验证（会走 tag 流程，同时产出 `X.Y.Z` / `X.Y` / `latest`）：

```sh
git tag v0.1.0 && git push origin v0.1.0
```

成功后：

- Docker Hub：`0.1.0`、`0.1`、`latest`
- GitLab Registry：`0.1.0`、`0.1`、`latest`

再往默认分支推一个普通提交，验证 nightly：

```sh
git commit --allow-empty -m "chore: trigger nightly" && git push
```

Docker Hub 应该多出 `sha-<短哈希>` 和 `nightly`；GitLab Registry 不应变化。

## 本地构建推送

CI 的打标签逻辑在 `scripts/ci-docker.sh` 里，本地也能用（`DRY_RUN=1` 只打印命令）：

```sh
DOCKERHUB_USER=me ./scripts/ci-docker.sh nightly
DOCKERHUB_USER=me CI_COMMIT_TAG=v1.2.3 \
  CI_REGISTRY_IMAGE=registry.example.com/me/keycordon \
  ./scripts/ci-docker.sh release
```
