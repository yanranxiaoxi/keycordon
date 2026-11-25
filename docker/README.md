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

`CI_REGISTRY_USER` / `CI_REGISTRY_PASSWORD` / `CI_REGISTRY_IMAGE` 由 GitLab 自动注入，不用配。GitLab 自己的 Container Registry 需要在项目里启用：Settings → General → Visibility → Container Registry。

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
