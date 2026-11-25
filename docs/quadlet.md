# 用 Quadlet 部署

Quadlet 是 Podman 的 systemd 集成：写一个 `.container` 文件，systemd 在 `daemon-reload` 时把它转换成 `.service`，由 systemd 负责启动、重启、开机自启。不需要额外写 `ExecStart=podman run ...`。

仓库里提供的单元文件：[deploy/quadlet/keycordon.container](../deploy/quadlet/keycordon.container)。

## 1. 准备镜像

二选一：

```sh
# 从 Docker Hub 拉（CI 已发布）
podman pull docker.io/xiaoxi/keycordon:latest

# 或者本地构建
podman build -t keycordon:latest .
```

镜像标签按需选：

| 标签 | 含义 |
|---|---|
| `latest` | 最新**发布版本**（推荐） |
| `1.2.3` / `1.2` | 固定版本 |
| `nightly` | 默认分支最新构建，**只推 Docker Hub** |
| `sha-<短哈希>` | 某一次提交，不可变 |

## 2. 放单元文件

**rootless（推荐）**

```sh
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/keycordon.container ~/.config/containers/systemd/
$EDITOR ~/.config/containers/systemd/keycordon.container   # 改 Image 和 Exec 里的上游地址
```

**root**

```sh
sudo cp deploy/quadlet/keycordon.container /etc/containers/systemd/
sudo $EDITOR /etc/containers/systemd/keycordon.container
```

root 部署时把文件最后的 `WantedBy=default.target` 改成 `WantedBy=multi-user.target`，否则 `enable` 会报「unit has no installation config」。

## 3. 必须改的三处

```ini
# ① 镜像
Image=docker.io/xiaoxi/keycordon:latest

# ② 上游地址：容器里的 127.0.0.1 是容器自己，不是宿主机
Exec=serve -config /etc/keycordon/config.yaml -upstream http://host.containers.internal:8317

# ③ 端口暴露范围
PublishPort=127.0.0.1:8318:8318
```

**上游怎么填**：

| 上游在哪 | 写法 |
|---|---|
| 宿主机上的 CLIProxyAPI | `http://host.containers.internal:8317` |
| 同一个 Podman 网络的另一个容器（如 `cpa`） | `http://cpa:8317`，并给两边加同一个 `Network=` |
| 厂商 API 直连 | `https://api.example.com` |

**端口**：默认只发布到 `127.0.0.1`。keycordon 用客户端的 API key 识别调用方，但没必要让它暴露在网络上。如果确实需要（比如 agent 在另一台机器上），改成 `0.0.0.0:8318:8318`，并确认客户端**都带凭据**——容器里 `caller.require_on_non_loopback` 默认为 `true`，不带凭据的请求会 401 而不是共用一个 vault。

## 4. 启动

```sh
systemctl --user daemon-reload
systemctl --user start keycordon
systemctl --user status keycordon
journalctl --user -u keycordon -f
```

root 部署把 `--user` 去掉、`journalctl --user -u` 换成 `journalctl -u`。

验证：

```sh
curl -sS http://127.0.0.1:8318/_keycordon/healthz
```

```json
{"adapters":26,"mode":"enforce","version":"1.2.3","master_key_fingerprint":"...","status":"ok"}
```

## 5. 开机自启（rootless 的关键一步）

rootless 的 user unit 默认**在用户登录后才启动**。要让它在开机时就跑（否则重启后 agent 的第一个请求会失败，直到你登录）：

```sh
loginctl enable-linger "$USER"
systemctl --user enable keycordon
```

`enable-linger` 之后，该用户的服务在开机时就会启动，不需要登录。

root 部署只需要 `sudo systemctl enable keycordon`。

## 6. 主密钥

默认写在卷里：

```ini
Volume=keycordon-data:/var/lib/keycordon
```

首次启动生成 `/var/lib/keycordon/master.key`（`0600`，属主 uid 10001）。

**主密钥不变，占位符就不变，上游的前缀缓存也就不会因为重启而失效。** 所以这个卷要保留——删了卷等于换了一套占位符，下一轮全量重算。

不想把密钥放在卷里，改用环境变量：

```ini
EnvironmentFile=%h/.config/keycordon/env
```

```sh
# ~/.config/keycordon/env
KEYCORDON_MASTER_KEY=<64 位 hex>
```

```sh
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
```

同时在配置里写 `vault.master_key_scope: env`。两种方式**不要混用**：环境变量存在时优先级更高，但切换会让占位符全变、缓存重算一次。

## 7. 自定义配置

镜像内自带容器默认配置（`/etc/keycordon/config.yaml`：监听 `0.0.0.0:8318`、`require_on_non_loopback: true`、主密钥走文件）。要覆盖就挂一份自己的：

```ini
Volume=%h/.config/keycordon/config.yaml:/etc/keycordon/config.yaml:ro,Z
```

```yaml
# ~/.config/keycordon/config.yaml
listen: 0.0.0.0:8318
mode: enforce
vault:
  master_key_scope: file
  master_key_file: /var/lib/keycordon/master.key
log:
  level: info
  format: json
```

`:Z` 是 SELinux 标签（Fedora / RHEL / Alma 需要）；Debian 系可以省略。

自定义协议适配器同理：

```ini
Volume=%h/.config/keycordon/protocols:/etc/keycordon/protocols:ro,Z
```

配置里写 `protocols.extra_dir: /etc/keycordon/protocols`。

## 8. 升级

**自动**（单元文件里默认开了 `AutoUpdate=registry`）：

```sh
systemctl --user enable --now podman-auto-update.timer   # 每天检查一次
```

systemd 会在镜像更新后重启容器。`latest` 和 `nightly` 这类移动标签才有意义；固定版本号不会变。

**手动**：

```sh
podman auto-update            # 或者
podman pull docker.io/xiaoxi/keycordon:latest
systemctl --user restart keycordon
```

卷里的主密钥不动，占位符就不变，升级不会打穿上游缓存。

## 9. 安全设置说明

单元文件里有三行：

```ini
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
```

- `ReadOnly=true`：根文件系统只读，只有卷和 `/tmp` 可写。实测过——镜像启动、生成主密钥、响应请求都正常。
- `NoNewPrivileges=true`：进程无法通过 setuid 提权。
- `Tmpfs=/tmp`：给只读根一个可写的临时目录。

镜像本身也已以固定非 root uid（10001）运行，这三行是额外的纵深防御。

## 10. 常见问题

**`systemctl --user start` 报 `Unit keycordon.service not found`**

没跑 `daemon-reload`。Quadlet 是在 `daemon-reload` 时生成 `.service` 的，不是启动时。

**`enable` 报 `unit has no installation config`**

root 部署时 `WantedBy` 还是 `default.target`，改成 `multi-user.target`。

**容器起来了但客户端连不上**

先看 `PublishPort`。默认是 `127.0.0.1:8318:8318`，只对本机开放。

**请求返回 401 `keycordon_no_credential`**

容器监听 `0.0.0.0`，`require_on_non_loopback: true` 生效，客户端必须带 `Authorization` / `x-api-key` / `x-goog-api-key` / `?key=` 之一。这是有意的：不带凭据的所有客户端会共用一个 vault。

**502 `keycordon_upstream_error`**

上游地址不对。容器里的 `127.0.0.1` 是容器自己，宿主机要用 `host.containers.internal`。

**日志在哪**

`journalctl --user -u keycordon`（rootless）或 `journalctl -u keycordon`（root）。单元文件里设了 `LogDriver=journald`，`podman logs` 也有。

**改了 `.container` 文件但没生效**

改完要 `systemctl --user daemon-reload` 再 `restart`。
