# Komari 代理流量排行

一个自托管的 Komari 插件：从 Clash API 或 Xray access log 采集代理连接，按来源 IP 汇总上传、下载、在线状态、地区、目标站点，并在 Komari 管理后台展示排行榜。支持 AnyTLS、VLESS、VMess、Trojan、Shadowsocks、Hysteria、TUIC 等协议。

> 作者：Syngnat
>
> 当前版本：1.9.0

## 功能

- 按来源 IP 统计上传、下载、连接数和活跃时间
- 支持多个节点同时显示与汇总，默认全部节点，可勾选任意节点组合
- 默认采集全部协议，也可以用 `protocols` 只保留指定协议
- 近 3 分钟有上报即视为在线，在线设备排在前面
- 统计口径中的节点名称来自接口 `node_name`，不写死具体节点
- 使用 IPinfo 解析国家、省州、城市和 ASN，本地缓存结果
- 支持 GeoLite2 / DB-IP 作为本地基础数据源
- 直辖市自动折叠为两级，镇名归并到地级市
- 自动聚类公网 IP 变化的“疑似设备”，也可以手动合并 IP
- 目标站点流量排行，显示每个站点的访问 IP 明细
- 每个 IP 的域名明细，支持“正在活跃”排序
- 过滤 IP-only、Cloudflare challenge、DNS / 连通性探针等噪声
- 所有查询接口仅允许 Komari 管理员访问

## 架构

```text
任意代理节点
  sing-box Clash API :9090
          │
          │ collector.py（每秒轮询，按分钟聚合，30 秒上传）
          ▼
HTTPS /api/proxy-traffic/ingest
          │
          ▼
聚合服务 server.py :9460（SQLite）
          │
          │ Komari 插件 script.js 反向代理
          ▼
Komari 管理页 iframe（traffic.html）
```

组件说明：

- `collector/collector.py`：部署在每个代理节点，读取 sing-box Clash API，默认采集全部入站连接，也支持按 `protocols` 白名单过滤。每个节点使用独立的 `node_id` / `node_name`。
- `server/server.py`：部署在 Komari 主机，接收多个节点的数据，做 GeoIP、设备聚类、目标站点和查询接口。
- `plugin/`：Komari 插件清单、路由代理和管理页。

## 环境要求

- Komari `>= 1.6.0`
- Python `>= 3.10`
- Clash 模式：内核开启 `/connections` 接口
- Xray 模式：开启 access log，并保证采集器可读
- 可选：`maxminddb` Python 包和 GeoLite2 / DB-IP 数据库
- 可选：IPinfo token（免费额度有限）

## 内核支持

| 内核 | 粒度 | 接入方式 |
|---|---|---|
| sing-box | 完整：来源 IP + 域名 + 上下行字节数 | Clash API `/connections`，已实测 |
| mihomo / Clash.Meta | 完整：来源 IP + 域名 + 上下行字节数 | Clash API `/connections`，字段兼容 |
| Xray / v2ray-core | 降级：来源 IP + 域名 + 连接次数 + 活跃时间 | `mode: "xray"`，读取 access log |
| Hysteria2 | 不完整：只有 `/traffic` 的用户总流量和 `/online` 在线设备 | 没有目标域名和每 IP 流量 |

Xray 的 access log 记录“谁在什么时候连接了哪个域名”，但不记录该连接的上下行字节数；Stats API 只按 inbound/user 汇总。因此，Xray 作为入口内核时只能使用降级模式，页面会明确显示“连接次数”，不会伪造流量。

如果需要给 Xray 生态保留完整粒度，推荐把入口换成 mihomo 或 sing-box：

```text
客户端 -> mihomo / sing-box 入口（VLESS、Reality 等）
                    │
                    ├─ 直接出站
                    └─ 或转发到本机 Xray/SOCKS5 上游
```

采集器部署在 mihomo / sing-box 入口，读取它的 Clash API；Xray 可以继续作为下游出站，但客户端不再直接连 Xray 入口。

如果 Xray 必须作为客户端直连的入口，则只能接受降级模式（连接次数/用户总量，不含每域名精确流量），或在 Xray 侧做自定义字节日志改造。

## 安装

### Docker 一键部署

聚合服务在 Komari 主机上运行：

```bash
cp .env.example .env
openssl rand -hex 32
# 把输出写入 .env 的 PROXY_TRAFFIC_INGEST_TOKEN
docker compose up -d --build
docker compose logs -f server
```

默认把聚合服务发布到 Docker 网桥网关 `172.17.0.1:9460`，与插件默认的 `BACKEND` 一致，不会监听公网 IP。如果宿主机的 Docker 网桥不是 `172.17.0.1`，修改 `.env` 的 `PROXY_TRAFFIC_HOST_IP`，并同步修改 `plugin/script.js` 的 `BACKEND`。

GeoIP 数据库可选，放在 `docker/geoip/`：

```text
docker/geoip/GeoLite2-City.mmdb
docker/geoip/GeoLite2-ASN.mmdb
docker/geoip/dbip-city-lite.mmdb
```

代理节点用 collector 容器：

```bash
mkdir -p collector-config
cp collector/config.example.json collector-config/config.json
# 编辑 config.json，填入 ingest_url、node_id、node_name
# 把 ingest token 写入 collector-config/ingest-token
docker compose -f docker-compose.collector.yml up -d --build
```

Clash 模式把 `clash-secret` 放进 `collector-config/`；Xray 模式把 `mode` 改为 `xray`、`access_log` 改为 `/var/log/xray/access.log`，并取消 `docker-compose.collector.yml` 里 access log 挂载的注释。

collector 使用 `network_mode: host`，因此 `clash_api: http://127.0.0.1:9090` 可以直接访问宿主机上的 Clash API；该配置适用于 Linux。Docker 方式仍需要从 Komari 插件市场安装插件。

### 1. 部署聚合服务

在 Komari 主机执行：

```bash
sudo useradd --system --home /var/lib/proxy-traffic --shell /usr/sbin/nologin proxy-traffic
sudo install -d -m 0750 -o proxy-traffic -g proxy-traffic /var/lib/proxy-traffic /etc/proxy-traffic
sudo install -d -m 0755 /opt/proxy-traffic
sudo install -m 0755 server/server.py /opt/proxy-traffic/server.py
sudo python3 -m venv /opt/proxy-traffic/venv
sudo /opt/proxy-traffic/venv/bin/pip install -r server/requirements.txt
```

生成采集令牌。令牌至少 24 个字符：

```bash
openssl rand -hex 32 | sudo tee /etc/proxy-traffic/ingest-token >/dev/null
sudo chown root:proxy-traffic /etc/proxy-traffic/ingest-token
sudo chmod 0640 /etc/proxy-traffic/ingest-token
```

可选：把 GeoLite2 / DB-IP 数据库放到以下位置。

```text
/opt/proxy-traffic/GeoLite2-City.mmdb
/opt/proxy-traffic/GeoLite2-ASN.mmdb
/opt/proxy-traffic/dbip-city-lite.mmdb
```

安装 systemd 服务：

```bash
sudo install -m 0644 deploy/systemd/proxy-traffic.service /etc/systemd/system/proxy-traffic.service
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-traffic
curl -s http://172.17.0.1:9460/healthz
```

如果 Komari 的 Docker 网桥不是 `172.17.0.1`，用 `docker network inspect bridge` 确认网关地址，再修改服务里的 `PROXY_TRAFFIC_BIND` 和插件里的 `BACKEND`。

### 2. 配置 HTTPS 入口

采集器可能在其他 VPS 上，需要通过 HTTPS 把数据送到聚合服务。只暴露 ingest 路径，不要暴露查询接口：

```bash
sudo install -m 0644 deploy/nginx-proxy-traffic.conf.example /etc/nginx/snippets/proxy-traffic.conf
```

把 snippet 引入 Komari 站点的 `server {}`，替换域名后执行：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

示例配置见 `deploy/nginx-proxy-traffic.conf.example`。

### 3. 部署采集器

在每个代理节点执行：

```bash
sudo useradd --system --home /var/lib/proxy-traffic --shell /usr/sbin/nologin proxy-traffic
sudo install -d -m 0750 -o proxy-traffic -g proxy-traffic /var/lib/proxy-traffic /etc/proxy-traffic
sudo install -d -m 0755 /opt/proxy-traffic
sudo install -m 0755 collector/collector.py /opt/proxy-traffic/collector.py
sudo install -m 0640 -o root -g proxy-traffic collector/config.example.json /etc/proxy-traffic/config.json
```

编辑 `/etc/proxy-traffic/config.json`：

```json
{
  "mode": "clash",
  "clash_api": "http://127.0.0.1:9090",
  "clash_secret_file": "/etc/proxy-traffic/clash-secret",
  "ingest_url": "https://komari.example.com/api/proxy-traffic/ingest",
  "ingest_token_file": "/etc/proxy-traffic/ingest-token",
  "protocols": ["*"],
  "node_id": "lax-01",
  "node_name": "LAX-01",
  "db_path": "/var/lib/proxy-traffic/traffic.db"
}
```

把聚合服务的 ingest token 写入 `/etc/proxy-traffic/ingest-token`，把 sing-box Clash API 的 secret 写入 `/etc/proxy-traffic/clash-secret`：

```bash
sudo chown root:proxy-traffic /etc/proxy-traffic/ingest-token /etc/proxy-traffic/clash-secret
sudo chmod 0640 /etc/proxy-traffic/ingest-token /etc/proxy-traffic/clash-secret
```

安装并启动：

```bash
sudo install -m 0644 deploy/systemd/proxy-traffic-collector.service /etc/systemd/system/proxy-traffic-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-traffic-collector
sudo journalctl -u proxy-traffic-collector -f
```

`node_id` 是稳定且唯一的节点标识，发布后不要随意修改，否则历史数据会归到新节点。`node_name` 是页面显示名称。

#### Xray 降级模式

Xray 节点使用 access log 模式，不需要 Clash API。先确保 Xray 开启访问日志：

```json
{
  "log": {
    "access": "/var/log/xray/access.log",
    "loglevel": "warning"
  }
}
```

采集器配置示例见 `collector/config.xray.example.json`：

```json
{
  "mode": "xray",
  "access_log": "/var/log/xray/access.log",
  "xray_log_start_at_end": true,
  "ingest_url": "https://komari.example.com/api/proxy-traffic/ingest",
  "ingest_token_file": "/etc/proxy-traffic/ingest-token",
  "node_id": "xray-01",
  "node_name": "Xray-01",
  "db_path": "/var/lib/proxy-traffic/traffic.db"
}
```

该模式只能统计 access log 中出现的来源 IP、目标域名、连接次数和活跃时间；上下行字节数为 0，页面会自动切换为“连接次数”视图。要恢复完整流量粒度，请使用 mihomo/sing-box 入口。

#### 多节点

每个节点单独运行一个采集器，使用不同的 `node_id` 和 `node_name`。聚合服务会自动接收并展示所有已上报节点，无需在插件里预先写死节点名单。

例如节点 A：

```json
{
  "clash_api": "http://127.0.0.1:9090",
  "clash_secret_file": "/etc/proxy-traffic/clash-secret",
  "ingest_url": "https://komari.example.com/api/proxy-traffic/ingest",
  "ingest_token_file": "/etc/proxy-traffic/ingest-token",
  "node_id": "lax-01",
  "node_name": "LAX-01",
  "db_path": "/var/lib/proxy-traffic/traffic.db"
}
```

节点 B 的配置保留节点 A 的其他字段，只替换 `node_id` 和 `node_name`：

```json
{
  "node_id": "hkg-01",
  "node_name": "HKG-01"
}
```

页面右上角的“节点”菜单支持多选：

- 默认选择全部节点。
- 可只勾选一个或多个节点，汇总卡片、设备排行、IP 明细和目标站点会按所选节点合并。
- 设备的手动归并按节点隔离，一次只能合并同一节点下的来源 IP。

### 4. 从 GitHub 插件市场安装

在 Komari 管理后台的插件市场中添加自定义源：

```text
https://fastly.jsdelivr.net/gh/Syngnat/komari-proxy-traffic@main/v1.json
```

刷新市场目录后选择“代理流量排行”，点击安装。Komari 会从本仓库的 GitHub Release 下载 ZIP，校验 SHA-256 后解压到插件目录。

使用 jsDelivr 而不是 `raw.githubusercontent.com` 的 `main` 地址，是为了避开 GitHub Raw 的 CDN 缓存，发布新版本后市场能更快读到清单；Fastly 节点通常比默认 jsDelivr 节点刷新更快。

市场清单文件为 [`v1.json`](v1.json)，安装包为对应版本的 Release 资源。

本地文件复制只用于开发调试，不建议作为生产安装方式。

#### 开发调试安装

把 `plugin/` 下的内容复制到 Komari 数据目录：

```text
<komari-data>/plugin/proxy-traffic/
├── komari-plugin.json
├── script.js
└── pages/traffic.html
```

例如当前常见部署：

```bash
sudo install -d -m 0755 /opt/komari/data/plugin/proxy-traffic/pages
sudo install -m 0644 plugin/komari-plugin.json /opt/komari/data/plugin/proxy-traffic/
sudo install -m 0644 plugin/script.js /opt/komari/data/plugin/proxy-traffic/
sudo install -m 0644 plugin/pages/traffic.html /opt/komari/data/plugin/proxy-traffic/pages/
docker restart komari
```

在 Komari 管理后台确认插件已加载，并打开“代理流量排行”页面。

插件清单要求目录名与 `short` 一致，即 `proxy-traffic`。

## 配置说明

### 聚合服务环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PROXY_TRAFFIC_BIND` | `172.17.0.1` | 监听地址，默认使用 Docker 网桥网关 |
| `PROXY_TRAFFIC_PORT` | `9460` | 监听端口 |
| `PROXY_TRAFFIC_DB` | `/var/lib/proxy-traffic/aggregate.db` | 聚合数据库 |
| `PROXY_TRAFFIC_TOKEN_FILE` | `/etc/proxy-traffic/ingest-token` | ingest bearer token 文件 |
| `PROXY_TRAFFIC_GEOIP_CITY` | `/opt/proxy-traffic/GeoLite2-City.mmdb` | 可选城市库 |
| `PROXY_TRAFFIC_GEOIP_ASN` | `/opt/proxy-traffic/GeoLite2-ASN.mmdb` | 可选 ASN 库 |
| `PROXY_TRAFFIC_GEOIP_CITY_FALLBACK` | `/opt/proxy-traffic/dbip-city-lite.mmdb` | 可选城市回退库 |
| `IPINFO_TOKEN` | 空 | 可选 IPinfo token，不填也能用免费额度 |

### 采集器配置

| 字段 | 必填 | 说明 |
|---|---|---|
| `mode` | 否 | `clash`（默认，sing-box/mihomo）或 `xray` |
| `clash_api` | Clash 模式必填 | Clash API 地址 |
| `clash_secret_file` | Clash 模式必填 | Clash API secret 文件 |
| `access_log` | Xray 模式必填 | Xray access log 路径 |
| `xray_log_start_at_end` | 否 | Xray 首次启动是否从文件末尾开始，默认 `true` |
| `ingest_url` | 是 | 聚合服务的 ingest 地址 |
| `ingest_token` | 二选一 | 直接填写 token，不推荐 |
| `ingest_token_file` | 二选一 | token 文件路径，推荐 |
| `protocols` | 否 | 仅 Clash 模式使用；默认 `["*"]` 表示全部协议，也可填 `["anytls", "vless"]` 等 |
| `node_id` | 是 | 唯一、稳定、最多 64 字符 |
| `node_name` | 是 | 页面显示名，最多 120 字符 |
| `db_path` | 否 | 本地队列数据库，默认 `/var/lib/proxy-traffic/traffic.db` |

## 统计口径与限制

- **Clash 模式采集聚合元数据**：来源 IP、上下行字节数、连接数、连接开始/结束时间、目标主机名或 IP。不采集 UA、URL 路径、查询参数、Referer 或页面内容。
- **Xray 降级模式只采集 access log 事件**：来源 IP、目标域名、连接次数和活跃时间；没有每域名精确流量。access log 必须为文本文件并开启 `log.access`。
- **共享密码无法可靠区分设备**：多个用户共用同一个代理密码时，只能按来源 IP 和设备行为推断，不能做严格身份归属。
- **“疑似设备”是启发式**：依据同国家 / ASN、地区一致、活跃分钟不重叠和 IP 切换间隔聚类，必须人工确认。IP 变化频繁或多人同时在线时可能误合并。设备归并只在单个节点内生效。
- **链式代理有观测边界**：入口节点看到的是下游入口 IP。若下游再做代理，入口节点看不到隧道内的最终域名。
- **地区可能漂移**：IPinfo 和 GeoIP 数据库的城市级结果只作参考，尤其是移动网络、Anycast 和企业出口。
- **Clash 模式默认统计全部协议**：采集器会统计 Clash API 中所有具有公网来源 IP 的连接；如需排除某些协议，可把 `protocols` 设成前缀白名单，例如 `["anytls", "vless"]`。Xray 模式以 access log 中实际出现的 accepted 连接为准。
- **在线窗口为 3 分钟**：最近 3 分钟有上报视为在线；不是实时 TCP 连接数。
- **目标站点只保留主机名 / IP**：不会还原完整 URL。
- **数据保留 30 天**：聚合服务自动清理超过 30 天的分钟数据。
- **IPinfo 有配额**：未配置 token 时受共享免费额度限制；查询结果会写入本地 `ip_geo` 缓存。
- **不包含 GeoIP 数据库**：GeoLite2 / DB-IP 的授权和下载由部署者自行处理。

## 数据与安全

- SQLite 数据库包含公网 IP、目标域名和流量统计，应按敏感运维数据处理。
- ingest token 使用 Bearer 认证和常量时间比较；请使用至少 24 字符的随机值。
- 只通过 HTTPS 暴露 `/api/proxy-traffic/ingest`，不要把聚合服务的其他路径直接暴露到公网。
- Komari 插件的查询路由只允许带有 `admin` 角色的管理员访问。
- 建议保持 `UMask=0077`，并确保 `/var/lib/proxy-traffic` 仅服务用户可读。

## 验证

```bash
python3 -m json.tool plugin/komari-plugin.json >/dev/null
node --check plugin/script.js
awk '/<script>/{f=1;next}/<\/script>/{f=0}f' plugin/pages/traffic.html > /tmp/traffic.js
node --check /tmp/traffic.js
python3 -m py_compile server/server.py collector/collector.py
```

## 许可

MIT License，详见 [LICENSE](LICENSE)。
