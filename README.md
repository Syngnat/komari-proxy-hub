# Komari 代理流量排行

一个自托管的 Komari 插件：从 AnyTLS 节点的 sing-box Clash API 采集连接，按来源 IP 汇总上传、下载、在线状态、地区、目标站点，并在 Komari 管理后台展示排行榜。

> 作者：Syngnat
>
> 当前版本：1.4.1

## 功能

- 按来源 IP 统计上传、下载、连接数和活跃时间
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
AnyTLS 节点
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

- `collector/collector.py`：部署在每个 AnyTLS 节点，读取 sing-box Clash API，过滤出 AnyTLS 入站连接并上传分钟级聚合数据。
- `server/server.py`：部署在 Komari 主机，接收多个节点的数据，做 GeoIP、设备聚类、目标站点和查询接口。
- `plugin/`：Komari 插件清单、路由代理和管理页。

## 环境要求

- Komari `>= 1.6.0`
- Python `>= 3.10`
- 节点使用 sing-box，且开启 Clash API
- 节点连接类型为 AnyTLS
- 可选：`maxminddb` Python 包和 GeoLite2 / DB-IP 数据库
- 可选：IPinfo token（免费额度有限）

## 安装

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

在每个 AnyTLS 节点执行：

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
  "clash_api": "http://127.0.0.1:9090",
  "clash_secret_file": "/etc/proxy-traffic/clash-secret",
  "ingest_url": "https://komari.example.com/api/proxy-traffic/ingest",
  "ingest_token_file": "/etc/proxy-traffic/ingest-token",
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

### 4. 安装 Komari 插件

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
| `clash_api` | 是 | sing-box Clash API 地址 |
| `clash_secret_file` | 是 | Clash API secret 文件 |
| `ingest_url` | 是 | 聚合服务的 ingest 地址 |
| `ingest_token` | 二选一 | 直接填写 token，不推荐 |
| `ingest_token_file` | 二选一 | token 文件路径，推荐 |
| `node_id` | 是 | 唯一、稳定、最多 64 字符 |
| `node_name` | 是 | 页面显示名，最多 120 字符 |
| `db_path` | 否 | 本地队列数据库，默认 `/var/lib/proxy-traffic/traffic.db` |

## 统计口径与限制

- **只采集聚合元数据**：来源 IP、上下行字节数、连接数、连接开始/结束时间、目标主机名或 IP。不采集 UA、URL 路径、查询参数、Referer 或页面内容。
- **共享密码无法可靠区分设备**：多个用户共用同一个 AnyTLS 密码时，只能按来源 IP 和设备行为推断，不能做严格身份归属。
- **“疑似设备”是启发式**：依据同国家 / ASN、地区一致、活跃分钟不重叠和 IP 切换间隔聚类，必须人工确认。IP 变化频繁或多人同时在线时可能误合并。
- **链式代理有观测边界**：入口节点看到的是下游入口 IP。若下游再做代理，入口节点看不到隧道内的最终域名。
- **地区可能漂移**：IPinfo 和 GeoIP 数据库的城市级结果只作参考，尤其是移动网络、Anycast 和企业出口。
- **只统计 AnyTLS**：采集器只处理 `type` 以 `anytls` 开头的连接。
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
