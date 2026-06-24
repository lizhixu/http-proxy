# http-proxy

轻量级 HTTP 代理，Go 标准库实现，零依赖，支持 Docker 一键部署。可作为 Clash、V2Ray 等工具的代理节点使用。

## 特性

- HTTP / HTTPS 隧道代理
- 用户名/密码认证
- `sync.Pool` 缓冲复用，低内存占用
- 多阶段构建，镜像约 2MB
- 零外部依赖

## 快速开始

### Docker Compose

```bash
docker compose up -d
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `7890` | 代理端口 |
| `PROXY_USER` | *(空)* | 用户名（留空则无认证） |
| `PROXY_PASS` | *(空)* | 密码（留空则无认证） |

### 本地运行

```bash
PROXY_USER=user PROXY_PASS=pass go run main.go
```

## Clash 配置

在 `proxies` 下添加：

```yaml
proxies:
  - name: my-proxy
    type: http
    server: your-server-ip
    port: 7890
    username: user
    password: pass
```

## 项目结构

```
.
├── main.go            # 代理核心
├── Dockerfile         # 多阶段构建
├── docker-compose.yml
└── go.mod
```

## License

MIT
