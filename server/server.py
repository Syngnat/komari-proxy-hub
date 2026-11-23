#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

try:
    import yaml
except ImportError:
    yaml = None

VENDOR_DIR = Path(__file__).resolve().parent / 'vendor'
if VENDOR_DIR.is_dir():
    sys.path.insert(0, str(VENDOR_DIR))
try:
    import maxminddb
except ImportError:
    maxminddb = None

BIND_ADDRESS = os.environ.get('PROXY_TRAFFIC_BIND', '172.17.0.1')
PORT = int(os.environ.get('PROXY_TRAFFIC_PORT', '9460'))
DB_PATH = Path(os.environ.get('PROXY_TRAFFIC_DB', '/var/lib/proxy-traffic/aggregate.db'))
TOKEN_PATH = Path(os.environ.get('PROXY_TRAFFIC_TOKEN_FILE', '/etc/proxy-traffic/ingest-token'))
GEOIP_CITY_PATH = Path(os.environ.get(
    'PROXY_TRAFFIC_GEOIP_CITY', '/opt/proxy-traffic/GeoLite2-City.mmdb'
))
GEOIP_ASN_PATH = Path(os.environ.get(
    'PROXY_TRAFFIC_GEOIP_ASN', '/opt/proxy-traffic/GeoLite2-ASN.mmdb'
))
GEOIP_CITY_FALLBACK_PATH = Path(os.environ.get(
    'PROXY_TRAFFIC_GEOIP_CITY_FALLBACK',
    '/opt/proxy-traffic/dbip-city-lite.mmdb',
))
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_ROWS = 5000
MAX_SITE_ROWS = 5000
MAX_HOURS = 30 * 24
RETENTION_DAYS = 30
ONLINE_WINDOW_SECONDS = 3 * 60
IPINFO_TIMEOUT_SECONDS = 3
AUTO_GAP_MINUTES = 10
AUTO_HIGH_CONFIDENCE_MINUTES = 3
SUB_BASE_URL = os.environ.get('PROXY_TRAFFIC_SUB_BASE_URL', '').strip().rstrip('/')
RULE_DIR = Path(os.environ.get('PROXY_TRAFFIC_RULES_DIR', '/var/www/premium'))
RULE_PUBLIC_BASE = os.environ.get(
    'PROXY_TRAFFIC_RULE_PUBLIC_BASE', 'https://premium.syngnat.top'
).strip().rstrip('/')
RULE_TARGET_IP = os.environ.get(
    'PROXY_TRAFFIC_RULE_TARGET_IP', ''
).strip()
RULE_TARGET_NAME = os.environ.get(
    'PROXY_TRAFFIC_RULE_TARGET_NAME', ''
).strip()
NODE_ID_RE = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
SITE_RE = re.compile(r'^[A-Za-z0-9._:-]{1,253}$')
SUB_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{16,128}$')
SUB_CODE_RE = re.compile(r'^[A-Za-z0-9_-]{4,32}$')
SUBSCRIPTION_PROTOCOLS = {
    'vless', 'vmess', 'trojan', 'ss', 'shadowsocks', 'hysteria2',
    'tuic', 'anytls', 'raw',
}
NOISE_SITE_EXACT = {
    'ab.chatgpt.com',
    'accounts.google.com',
    'beacons.gcp.gvt2.com',
    'challenges.cloudflare.com',
    'clientservices.googleapis.com',
    'clients4.google.com',
    'c.pki.goog',
    'dns.cloudflare.com',
    'dns.google',
    'js.stripe.com',
    'm.stripe.com',
    'm.stripe.network',
    'oauthaccountmanager.googleapis.com',
    'optimizationguide-pa.googleapis.com',
    'ping.ldstatic.com',
    'safebrowsing.google.com',
    'safebrowsing.googleapis.com',
}
NOISE_SITE_SUFFIXES = ('.challenges.cloudflare.com', '.gvt2.com')
INGEST_PATHS = {'/ingest', '/api/proxy-traffic/ingest'}
SUMMARY_PATHS = {'/summary', '/api/proxy-traffic/summary'}
TIMELINE_PATHS = {'/timeline', '/api/proxy-traffic/timeline'}
HEALTH_PATHS = {'/healthz', '/api/proxy-traffic/health'}
DEVICE_MAP_PATHS = {'/device-map', '/api/proxy-traffic/device-map'}
IP_SITES_PATHS = {'/ip-sites', '/api/proxy-traffic/ip-sites'}

REGION_NAME_ZH = {
    'Beijing': '北京', 'Tianjin': '天津', 'Hebei': '河北', 'Shanxi': '山西',
    'Inner Mongolia': '内蒙古', 'Liaoning': '辽宁', 'Jilin': '吉林',
    'Heilongjiang': '黑龙江', 'Shanghai': '上海', 'Jiangsu': '江苏',
    'Zhejiang': '浙江', 'Anhui': '安徽', 'Fujian': '福建', 'Jiangxi': '江西',
    'Shandong': '山东', 'Henan': '河南', 'Hubei': '湖北', 'Hunan': '湖南',
    'Guangdong': '广东', 'Guangxi': '广西', 'Hainan': '海南',
    'Chongqing': '重庆', 'Sichuan': '四川', 'Guizhou': '贵州', 'Yunnan': '云南',
    'Tibet': '西藏', 'Shaanxi': '陕西', 'Gansu': '甘肃', 'Qinghai': '青海',
    'Ningxia': '宁夏', 'Xinjiang': '新疆', 'Hong Kong': '香港',
    'Macau': '澳门', 'Taiwan': '台湾',
}
CITY_NAME_ZH = {
    'Guangzhou': '广州', 'Shenzhen': '深圳', 'Dongguan': '东莞',
    'Huizhou': '惠州', 'Changsha': '长沙', 'Wuhan': '武汉',
    'Humen': '东莞', 'Wangniudun': '东莞',
    '虎门': '东莞', '望牛墩': '东莞',
    'Shanghai': '上海', 'Beijing': '北京', 'Hangzhou': '杭州',
    'Nanjing': '南京', 'Chengdu': '成都', 'Chongqing': '重庆',
    'Tianjin': '天津', 'Xi’an': '西安', "Xi'an": '西安',
}
COUNTRY_NAME_ZH = {'CN': '中国'}
MUNICIPALITY_REGIONS = {'北京', '上海', '天津', '重庆', '香港', '澳门'}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z',
)
log = logging.getLogger('proxy-traffic-aggregate')


def now_ms() -> int:
    return int(time.time() * 1000)


def load_token() -> str:
    token = os.environ.get('PROXY_TRAFFIC_INGEST_TOKEN', '').strip()
    if not token:
        token = TOKEN_PATH.read_text(encoding='utf-8').strip()
    if len(token) < 24:
        raise RuntimeError('ingest token is too short')
    return token


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=15000')
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    try:
        conn.executescript(
            '''
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                node_name TEXT NOT NULL,
                metric_mode TEXT NOT NULL DEFAULT 'traffic',
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS minute_agg (
                node_id TEXT NOT NULL,
                minute_ms INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                up_bytes INTEGER NOT NULL,
                down_bytes INTEGER NOT NULL,
                connections INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (node_id, minute_ms, source_ip)
            );
            CREATE INDEX IF NOT EXISTS idx_minute_agg_minute ON minute_agg(minute_ms);
            CREATE INDEX IF NOT EXISTS idx_minute_agg_node_minute ON minute_agg(node_id, minute_ms);
            CREATE TABLE IF NOT EXISTS ip_geo (
                ip TEXT PRIMARY KEY,
                country_code TEXT NOT NULL DEFAULT '',
                country_name TEXT NOT NULL DEFAULT '',
                region_name TEXT NOT NULL DEFAULT '',
                city_name TEXT NOT NULL DEFAULT '',
                asn INTEGER NOT NULL DEFAULT 0,
                asn_org TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_ip_map (
                node_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_label TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (node_id, source_ip)
            );
            CREATE INDEX IF NOT EXISTS idx_device_ip_map_node ON device_ip_map(node_id);
            CREATE TABLE IF NOT EXISTS site_minute_agg (
                node_id TEXT NOT NULL,
                minute_ms INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                site TEXT NOT NULL,
                up_bytes INTEGER NOT NULL,
                down_bytes INTEGER NOT NULL,
                connections INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (node_id, minute_ms, source_ip, site)
            );
            CREATE INDEX IF NOT EXISTS idx_site_minute_agg_window
                ON site_minute_agg(node_id, minute_ms);
            CREATE INDEX IF NOT EXISTS idx_site_minute_agg_site
                ON site_minute_agg(node_id, site, minute_ms);
            CREATE TABLE IF NOT EXISTS subscription_nodes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                user_id TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT '',
                flow TEXT NOT NULL DEFAULT '',
                security TEXT NOT NULL DEFAULT '',
                sni TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL DEFAULT '',
                short_id TEXT NOT NULL DEFAULT '',
                network TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                service_name TEXT NOT NULL DEFAULT '',
                extra_json TEXT NOT NULL DEFAULT '{}',
                share_link TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                external_key TEXT UNIQUE,
                origin_node_id TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subscription_nodes_updated
                ON subscription_nodes(updated_at_ms);
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                short_code TEXT NOT NULL UNIQUE,
                base_url TEXT NOT NULL DEFAULT '',
                format TEXT NOT NULL DEFAULT 'auto',
                include_all INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_node_map (
                subscription_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (subscription_id, node_id)
            );
            CREATE INDEX IF NOT EXISTS idx_subscription_node_map_node
                ON subscription_node_map(node_id);
            '''
        )
        ip_geo_columns = {
            row[1] for row in conn.execute('PRAGMA table_info(ip_geo)')
        }
        if 'source' not in ip_geo_columns:
            conn.execute(
                "ALTER TABLE ip_geo ADD COLUMN source TEXT NOT NULL DEFAULT ''"
            )
        node_columns = {
            row[1] for row in conn.execute('PRAGMA table_info(nodes)')
        }
        if 'metric_mode' not in node_columns:
            conn.execute(
                "ALTER TABLE nodes ADD COLUMN metric_mode TEXT NOT NULL DEFAULT 'traffic'"
            )
        subscription_columns = {
            row[1] for row in conn.execute('PRAGMA table_info(subscriptions)')
        }
        if 'include_all' not in subscription_columns:
            conn.execute(
                'ALTER TABLE subscriptions ADD COLUMN include_all INTEGER NOT NULL DEFAULT 0'
            )
        conn.commit()
        DB_PATH.chmod(0o600)
    finally:
        conn.close()


def prune(conn: sqlite3.Connection) -> None:
    cutoff = now_ms() - RETENTION_DAYS * 24 * 60 * 60 * 1000
    with conn:
        conn.execute('DELETE FROM minute_agg WHERE minute_ms < ?', (cutoff,))
        conn.execute('DELETE FROM site_minute_agg WHERE minute_ms < ?', (cutoff,))


def parse_hours(query: dict[str, list[str]]) -> int:
    raw = (query.get('hours') or ['24'])[0]
    try:
        hours = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('hours must be an integer') from exc
    if hours < 1 or hours > MAX_HOURS:
        raise ValueError(f'hours must be between 1 and {MAX_HOURS}')
    return hours


def parse_ip(value: str | None) -> str:
    if not value:
        raise ValueError('ip is required')
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError('invalid ip') from exc
    if not address.is_global:
        raise ValueError('ip must be public')
    return address.compressed


def source_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('invalid source_ip')
    address = ipaddress.ip_address(value.strip())
    if not address.is_global:
        raise ValueError('source_ip must be public')
    return address.compressed


GEO_CITY_READER = None
GEO_ASN_READER = None
GEO_CITY_FALLBACK_READER = None
GEO_LOCK = threading.Lock()
IPINFO_ATTEMPTED: set[str] = set()
IPINFO_LOCK = threading.Lock()


def open_geo_readers() -> None:
    global GEO_CITY_READER, GEO_ASN_READER, GEO_CITY_FALLBACK_READER
    if maxminddb is None:
        log.warning('maxminddb is not available; IP regions will be empty')
        return
    try:
        if GEOIP_CITY_PATH.is_file():
            GEO_CITY_READER = maxminddb.open_database(str(GEOIP_CITY_PATH))
            log.info('geoip city database opened: %s', GEOIP_CITY_PATH)
        if GEOIP_ASN_PATH.is_file():
            GEO_ASN_READER = maxminddb.open_database(str(GEOIP_ASN_PATH))
            log.info('geoip ASN database opened: %s', GEOIP_ASN_PATH)
        if GEOIP_CITY_FALLBACK_PATH.is_file():
            GEO_CITY_FALLBACK_READER = maxminddb.open_database(str(GEOIP_CITY_FALLBACK_PATH))
            log.info('geoip fallback city database opened: %s', GEOIP_CITY_FALLBACK_PATH)
    except Exception as exc:
        log.warning('geoip database open failed: %s', exc)


def country_flag(code: str) -> str:
    if len(code) != 2 or not code.isalpha():
        return ''
    return ''.join(chr(ord(char) + 127397) for char in code.upper())


def collapse_municipality_city(region: str, city: str) -> str:
    region = str(region or '').strip()
    city = str(city or '').strip()
    if not city:
        return ''
    region_core = region[:-1] if region.endswith('市') else region
    city_core = city[:-1] if city.endswith('市') else city
    if region_core == city_core and region_core in MUNICIPALITY_REGIONS:
        return ''
    return city


def geo_from_readers(ip: str) -> dict:
    city = {}
    asn = {}
    fallback = {}
    with GEO_LOCK:
        if GEO_CITY_READER is not None:
            try:
                city = GEO_CITY_READER.get(ip) or {}
            except (ValueError, TypeError):
                city = {}
        if GEO_ASN_READER is not None:
            try:
                asn = GEO_ASN_READER.get(ip) or {}
            except (ValueError, TypeError):
                asn = {}
        if GEO_CITY_FALLBACK_READER is not None:
            try:
                fallback = GEO_CITY_FALLBACK_READER.get(ip) or {}
            except (ValueError, TypeError):
                fallback = {}
    country = city.get('country') or fallback.get('country') or {}
    country_code = str(country.get('iso_code') or '')
    names = country.get('names') or {}
    subdivisions = city.get('subdivisions') or []
    subdivision = subdivisions[0] if subdivisions else {}
    sub_names = subdivision.get('names') or {}
    city_info = city.get('city') or {}
    city_names = city_info.get('names') or {}
    if not subdivision:
        fallback_subdivisions = fallback.get('subdivisions') or []
        if fallback_subdivisions:
            sub_names = (fallback_subdivisions[0].get('names') or {})
    if not city_info:
        fallback_city = fallback.get('city') or {}
        city_names = fallback_city.get('names') or {}
    region_name = str(sub_names.get('zh-CN') or sub_names.get('en') or '')
    city_name = str(city_names.get('zh-CN') or city_names.get('en') or '')
    region_name = REGION_NAME_ZH.get(region_name, region_name)
    city_name = CITY_NAME_ZH.get(city_name, city_name)
    if not country_code:
        country_code = str((fallback.get('country') or {}).get('iso_code') or '')
    if not names:
        names = (fallback.get('country') or {}).get('names') or {}
    asn_number = int(asn.get('autonomous_system_number') or 0)
    return {
        'country_code': country_code,
        'country_name': str(names.get('zh-CN') or names.get('en') or country_code),
        'country_flag': country_flag(country_code),
        'region_name': region_name,
        'city_name': city_name,
        'asn': asn_number,
        'asn_org': str(asn.get('autonomous_system_organization') or ''),
    }


def ipinfo_lookup(ip: str) -> dict | None:
    token = os.environ.get('IPINFO_TOKEN', '').strip()
    url = 'https://ipinfo.io/' + quote(ip, safe='') + '/json'
    if token:
        url += '?token=' + quote(token, safe='')
    request = urllib.request.Request(
        url,
        headers={
            'Accept': 'application/json',
            'User-Agent': 'komari-proxy-traffic/1',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=IPINFO_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        log.warning('ipinfo lookup failed for %s: %s', ip, type(exc).__name__)
        return None
    if not isinstance(payload, dict) or payload.get('bogon') or not payload.get('ip'):
        return None
    country_code = str(payload.get('country') or '').upper()
    region_raw = str(payload.get('region') or '').strip()
    city_raw = str(payload.get('city') or '').strip()
    region_name = REGION_NAME_ZH.get(region_raw, region_raw)
    city_name = CITY_NAME_ZH.get(city_raw, city_raw)
    asn = 0
    asn_org = ''
    org = str(payload.get('org') or '').strip()
    match = re.match(r'^AS(\d+)\s+(.*)$', org)
    if match:
        asn = int(match.group(1))
        asn_org = match.group(2).strip()
    return {
        'country_code': country_code,
        'country_name': COUNTRY_NAME_ZH.get(country_code, country_code),
        'region_name': region_name,
        'city_name': city_name,
        'asn': asn,
        'asn_org': asn_org,
    }


def lookup_geo(conn: sqlite3.Connection, ip: str) -> dict:
    row = conn.execute(
        '''SELECT country_code, country_name, region_name, city_name, asn, asn_org, source
           FROM ip_geo WHERE ip = ?''',
        (ip,),
    ).fetchone()
    if row and row['source'] in ('ipinfo', 'manual'):
        result = dict(row)
        result.pop('source', None)
        result['region_name'] = REGION_NAME_ZH.get(
            result.get('region_name'), result.get('region_name')
        )
        result['city_name'] = CITY_NAME_ZH.get(
            result.get('city_name'), result.get('city_name')
        )
        result['city_name'] = collapse_municipality_city(
            result.get('region_name', ''), result.get('city_name', '')
        )
        result['country_flag'] = country_flag(str(result.get('country_code') or ''))
        return result
    if row:
        result = dict(row)
        result.pop('source', None)
        result['country_flag'] = country_flag(str(result.get('country_code') or ''))
    else:
        result = None
    with IPINFO_LOCK:
        already_attempted = ip in IPINFO_ATTEMPTED
        if not already_attempted:
            IPINFO_ATTEMPTED.add(ip)
    ipinfo = None if already_attempted else ipinfo_lookup(ip)
    if ipinfo:
        base = geo_from_readers(ip)
        merged = dict(base)
        for key in ('country_code', 'country_name', 'region_name', 'city_name'):
            if ipinfo.get(key):
                merged[key] = ipinfo[key]
        if ipinfo.get('asn'):
            merged['asn'] = ipinfo['asn']
            merged['asn_org'] = ipinfo.get('asn_org') or merged.get('asn_org', '')
        merged['country_flag'] = country_flag(str(merged.get('country_code') or ''))
        result = merged
        source = 'ipinfo'
    else:
        if result is None:
            result = geo_from_readers(ip)
            result['country_flag'] = country_flag(str(result.get('country_code') or ''))
        source = row['source'] if row and row['source'] else 'local'
    result['city_name'] = collapse_municipality_city(
        result.get('region_name', ''), result.get('city_name', '')
    )
    with conn:
        conn.execute(
            '''INSERT OR REPLACE INTO ip_geo(
                   ip, country_code, country_name, region_name, city_name,
                   asn, asn_org, source, updated_at_ms
               ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                ip, result['country_code'], result['country_name'],
                result['region_name'], result['city_name'], result['asn'],
                result['asn_org'], source, now_ms(),
            ),
        )
    return result


def parse_ip_list(value: str | None) -> list[str]:
    if not value:
        raise ValueError('ips is required')
    result: list[str] = []
    seen: set[str] = set()
    for item in value.split(','):
        ip = parse_ip(item)
        if ip not in seen:
            result.append(ip)
            seen.add(ip)
    if not result or len(result) > 200:
        raise ValueError('ips must contain between 1 and 200 addresses')
    return result


def manual_device_map(conn: sqlite3.Connection, node_id: str) -> dict[str, dict]:
    rows = conn.execute(
        '''SELECT source_ip, device_id, device_label
           FROM device_ip_map WHERE node_id = ?''',
        (node_id,),
    ).fetchall()
    return {
        row['source_ip']: {
            'device_id': row['device_id'],
            'label': row['device_label'],
        }
        for row in rows
    }


def bounded_int(value: object, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f'{field} must be an integer')
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field} must be an integer') from exc
    if parsed < 0 or parsed > maximum:
        raise ValueError(f'{field} is out of range')
    return parsed


def normalize_site(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError('invalid site')
    site = value.strip().lower().rstrip('.')
    if not site or not SITE_RE.fullmatch(site):
        raise ValueError('invalid site')
    return site


def is_noise_site(site: str) -> bool:
    site = str(site or '').strip().lower().rstrip('.')
    if not site or site.startswith('ip:'):
        return True
    if site in NOISE_SITE_EXACT:
        return True
    return any(site.endswith(suffix) for suffix in NOISE_SITE_SUFFIXES)


def validate_ingest(
    payload: object, current_ms: int,
) -> tuple[
    str, str, str,
    list[tuple[int, str, int, int, int, int]],
    list[tuple[int, str, str, int, int, int, int]],
]:
    if not isinstance(payload, dict):
        raise ValueError('body must be an object')
    node_id = str(payload.get('node_id') or '').strip()
    node_name = str(payload.get('node_name') or '').strip()
    if not NODE_ID_RE.fullmatch(node_id):
        raise ValueError('invalid node_id')
    if not node_name or len(node_name) > 120:
        raise ValueError('invalid node_name')
    metric_mode = str(payload.get('metric_mode') or 'traffic').strip().lower()
    if metric_mode not in ('traffic', 'connections'):
        raise ValueError('invalid metric_mode')
    raw_rows = payload.get('rows') or []
    if not isinstance(raw_rows, list):
        raise ValueError('rows must be an array')
    if len(raw_rows) > MAX_ROWS:
        raise ValueError(f'too many rows, maximum is {MAX_ROWS}')
    oldest = current_ms - (RETENTION_DAYS + 2) * 24 * 60 * 60 * 1000
    newest = current_ms + 5 * 60 * 1000
    rows: list[tuple[int, str, int, int, int, int]] = []
    for index, item in enumerate(raw_rows):
        if not isinstance(item, list) or len(item) != 6:
            raise ValueError(f'row {index} must have 6 fields')
        minute_ms = bounded_int(item[0], f'row {index} minute', 2**63 - 1)
        if minute_ms % 60000 != 0:
            raise ValueError(f'row {index} minute is not aligned')
        if minute_ms < oldest or minute_ms > newest:
            raise ValueError(f'row {index} minute is outside the retention window')
        ip = source_ip(item[1])
        up_bytes = bounded_int(item[2], f'row {index} upload', 10**15)
        down_bytes = bounded_int(item[3], f'row {index} download', 10**15)
        connections = bounded_int(item[4], f'row {index} connections', 1000000)
        last_seen_ms = bounded_int(item[5], f'row {index} last_seen', 2**63 - 1)
        if last_seen_ms < oldest or last_seen_ms > newest:
            raise ValueError(f'row {index} last_seen is outside the retention window')
        rows.append((minute_ms, ip, up_bytes, down_bytes, connections, last_seen_ms))
    raw_site_rows = payload.get('site_rows') or []
    if not isinstance(raw_site_rows, list):
        raise ValueError('site_rows must be an array')
    if len(raw_site_rows) > MAX_SITE_ROWS:
        raise ValueError(f'too many site rows, maximum is {MAX_SITE_ROWS}')
    site_rows: list[tuple[int, str, str, int, int, int, int]] = []
    for index, item in enumerate(raw_site_rows):
        if not isinstance(item, list) or len(item) != 7:
            raise ValueError(f'site row {index} must have 7 fields')
        minute_ms = bounded_int(item[0], f'site row {index} minute', 2**63 - 1)
        if minute_ms % 60000 != 0:
            raise ValueError(f'site row {index} minute is not aligned')
        if minute_ms < oldest or minute_ms > newest:
            raise ValueError(f'site row {index} minute is outside the retention window')
        ip = source_ip(item[1])
        site = normalize_site(item[2])
        up_bytes = bounded_int(item[3], f'site row {index} upload', 10**15)
        down_bytes = bounded_int(item[4], f'site row {index} download', 10**15)
        connections = bounded_int(item[5], f'site row {index} connections', 1000000)
        last_seen_ms = bounded_int(item[6], f'site row {index} last_seen', 2**63 - 1)
        if last_seen_ms < oldest or last_seen_ms > newest:
            raise ValueError(f'site row {index} last_seen is outside the retention window')
        site_rows.append((
            minute_ms, ip, site, up_bytes, down_bytes, connections, last_seen_ms,
        ))
    return node_id, node_name, metric_mode, rows, site_rows


def ingest_rows(payload: object) -> int:
    current_ms = now_ms()
    node_id, node_name, metric_mode, rows, site_rows = validate_ingest(payload, current_ms)
    if not rows and not site_rows:
        return 0
    conn = db_connect()
    try:
        with conn:
            conn.execute(
                '''
                INSERT INTO nodes(node_id, node_name, metric_mode, first_seen_ms, last_seen_ms)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    node_name=excluded.node_name,
                    metric_mode=excluded.metric_mode,
                    first_seen_ms=MIN(nodes.first_seen_ms, excluded.first_seen_ms),
                    last_seen_ms=MAX(nodes.last_seen_ms, excluded.last_seen_ms)
                ''',
                (node_id, node_name, metric_mode, current_ms, current_ms),
            )
            conn.executemany(
                '''
                INSERT INTO minute_agg(
                    node_id, minute_ms, source_ip, up_bytes, down_bytes,
                    connections, last_seen_ms, updated_at_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, minute_ms, source_ip) DO UPDATE SET
                    up_bytes=excluded.up_bytes,
                    down_bytes=excluded.down_bytes,
                    connections=excluded.connections,
                    last_seen_ms=excluded.last_seen_ms,
                    updated_at_ms=excluded.updated_at_ms
                ''',
                [
                    (node_id, minute, ip, up_bytes, down_bytes, connections, last_seen, current_ms)
                    for minute, ip, up_bytes, down_bytes, connections, last_seen in rows
                ],
            )
            if site_rows:
                conn.executemany(
                    '''
                    INSERT INTO site_minute_agg(
                        node_id, minute_ms, source_ip, site, up_bytes, down_bytes,
                        connections, last_seen_ms, updated_at_ms
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id, minute_ms, source_ip, site) DO UPDATE SET
                        up_bytes=excluded.up_bytes,
                        down_bytes=excluded.down_bytes,
                        connections=excluded.connections,
                        last_seen_ms=excluded.last_seen_ms,
                        updated_at_ms=excluded.updated_at_ms
                    ''',
                    [
                        (
                            node_id, minute, ip, site, up_bytes, down_bytes,
                            connections, last_seen, current_ms,
                        )
                        for minute, ip, site, up_bytes, down_bytes, connections, last_seen
                        in site_rows
                    ],
                )
        return len(rows) + len(site_rows)
    finally:
        conn.close()


def activity_by_node(conn: sqlite3.Connection, start_ms: int) -> dict[str, dict[str, set[int]]]:
    activity: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    rows = conn.execute(
        'SELECT node_id, source_ip, minute_ms FROM minute_agg WHERE minute_ms >= ?',
        (start_ms,),
    )
    for row in rows:
        activity[row['node_id']][row['source_ip']].add(int(row['minute_ms']) // 60000)
    return activity


def minimum_gap_minutes(left: set[int], right: set[int]) -> int | None:
    if not left or not right:
        return None
    a = sorted(left)
    b = sorted(right)
    i = 0
    j = 0
    best = None
    while i < len(a) and j < len(b):
        gap = abs(a[i] - b[j])
        if best is None or gap < best:
            best = gap
        if gap == 0:
            return 0
        if a[i] < b[j]:
            i += 1
        else:
            j += 1
    return best


def same_geo_identity(left: dict, right: dict) -> bool:
    if left.get('country_code') and right.get('country_code'):
        if left['country_code'] != right['country_code']:
            return False
    if not left.get('asn') or left.get('asn') != right.get('asn'):
        return False
    if left.get('region_name') and right.get('region_name'):
        return left['region_name'] == right['region_name']
    return True


def auto_clusters(sources: list[dict], activity: dict[str, set[int]]) -> list[tuple[list[dict], str]]:
    count = len(sources)
    if count <= 1:
        return [(sources, 'single')] if sources else []
    parent = list(range(count))
    edge_gaps: dict[tuple[int, int], int] = {}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for left in range(count):
        left_source = sources[left]
        left_activity = activity.get(left_source['source_ip']) or set()
        for right in range(left + 1, count):
            right_source = sources[right]
            if not same_geo_identity(left_source, right_source):
                continue
            right_activity = activity.get(right_source['source_ip']) or set()
            if left_activity & right_activity:
                continue
            gap = minimum_gap_minutes(left_activity, right_activity)
            if gap is None or gap > AUTO_GAP_MINUTES:
                continue
            union(left, right)
            edge_gaps[(left, right)] = gap

    grouped: dict[int, list[int]] = defaultdict(list)
    for index in range(count):
        grouped[find(index)].append(index)

    result: list[tuple[list[dict], str]] = []
    for members in grouped.values():
        cluster_sources = [sources[index] for index in members]
        if len(cluster_sources) == 1:
            confidence = 'single'
        else:
            gaps = [
                gap for (left, right), gap in edge_gaps.items()
                if left in members and right in members
            ]
            high = bool(gaps) and max(gaps) <= AUTO_HIGH_CONFIDENCE_MINUTES
            if high:
                high = all(
                    (not sources[left].get('region_name') or
                     sources[left].get('region_name') == sources[right].get('region_name'))
                    for left in members for right in members if left < right
                )
            confidence = 'high' if high else 'medium'
        result.append((cluster_sources, confidence))
    return result


def device_region_label(sources: list[dict]) -> tuple[str, str]:
    regions = {
        ' · '.join(
            part for part in (
                source.get('country_flag'), source.get('country_name'),
                source.get('region_name'), source.get('city_name'),
            ) if part
        )
        for source in sources
        if source.get('country_name') or source.get('region_name') or source.get('city_name')
    }
    asns = {
        f"AS{source['asn']} {source.get('asn_org', '')}".strip()
        for source in sources if source.get('asn')
    }
    if not regions:
        region_label = '未知地区'
    elif len(regions) == 1:
        region_label = next(iter(regions))
    else:
        region_label = '多地区'
    asn_label = next(iter(asns)) if len(asns) == 1 else ('多运营商' if asns else '地区未知')
    return region_label, asn_label


def make_device(
    node_id: str,
    device_id: str,
    label: str,
    manual: bool,
    confidence: str,
    sources: list[dict],
) -> dict:
    sources = sorted(
        sources,
        key=lambda item: (int(item['last_seen_ms']), int(item['total'])),
        reverse=True,
    )
    latest = sources[0]
    online_sources = [item for item in sources if item.get('online')]
    region_label, asn_label = device_region_label(sources)
    upload = sum(int(item['upload']) for item in sources)
    download = sum(int(item['download']) for item in sources)
    active_minutes = sum(int(item['active_minutes']) for item in sources)
    connection_minutes = sum(int(item['connection_minutes']) for item in sources)
    connections = sum(
        int(item.get('connections', item['connection_minutes'])) for item in sources
    )
    for source in sources:
        source['device_id'] = device_id
        source['device_label'] = label
        source['manual_device'] = manual
    return {
        'device_id': device_id,
        'label': label,
        'manual': manual,
        'confidence': confidence,
        'region_label': region_label,
        'asn_label': asn_label,
        'latest_ip': latest['source_ip'],
        'latest_geo': {
            'country_flag': latest.get('country_flag', ''),
            'country_name': latest.get('country_name', ''),
            'region_name': latest.get('region_name', ''),
            'city_name': latest.get('city_name', ''),
        },
        'upload': upload,
        'download': download,
        'total': upload + download,
        'active_minutes': active_minutes,
        'connections': connections,
        'connection_minutes': connection_minutes,
        'first_seen_ms': min(int(item['first_seen_ms']) for item in sources),
        'last_seen_ms': max(int(item['last_seen_ms']) for item in sources),
        'ip_count': len(sources),
        'online': bool(online_sources),
        'online_ip_count': len(online_sources),
        'online_ips': [item['source_ip'] for item in online_sources],
        'ips': sources,
    }


def site_summary(hours: int) -> list[dict]:
    end_ms = now_ms()
    start_ms = end_ms - hours * 60 * 60 * 1000
    conn = db_connect()
    try:
        node_names = {
            row['node_id']: row['node_name']
            for row in conn.execute('SELECT node_id, node_name FROM nodes')
        }
        node_modes = {
            row['node_id']: row['metric_mode']
            for row in conn.execute('SELECT node_id, metric_mode FROM nodes')
        }
        rows = conn.execute(
            '''
            SELECT node_id, site, source_ip,
                   SUM(up_bytes) AS up_bytes,
                   SUM(down_bytes) AS down_bytes,
                   COUNT(*) AS active_minutes,
                   SUM(connections) AS connections,
                   MAX(last_seen_ms) AS last_seen_ms
            FROM site_minute_agg
            WHERE minute_ms >= ?
            GROUP BY node_id, site, source_ip
            ''',
            (start_ms,),
        ).fetchall()
    finally:
        conn.close()

    nodes: dict[str, dict] = {}
    for row in rows:
        if is_noise_site(row['site']):
            continue
        node_id = row['node_id']
        node = nodes.setdefault(node_id, {
            'node_id': node_id,
            'node_name': node_names.get(node_id, node_id),
            'metric_mode': node_modes.get(node_id, 'traffic'),
            'sites': [],
            'site_count': 0,
        })
        site_name = row['site']
        site = next((item for item in node['sites'] if item['site'] == site_name), None)
        if site is None:
            site = {
                'site': site_name,
                'upload': 0,
                'download': 0,
                'total': 0,
                'active_minutes': 0,
                'connections': 0,
                'connection_minutes': 0,
                'last_seen_ms': 0,
                'source_count': 0,
                'sources': [],
            }
            node['sites'].append(site)
        upload = int(row['up_bytes'])
        download = int(row['down_bytes'])
        connections = int(row['connections'])
        source = {
            'source_ip': row['source_ip'],
            'upload': upload,
            'download': download,
            'total': upload + download,
            'active_minutes': int(row['active_minutes']),
            'connections': connections,
            'connection_minutes': connections,
            'last_seen_ms': int(row['last_seen_ms']),
        }
        site['sources'].append(source)
        site['upload'] += upload
        site['download'] += download
        site['total'] += upload + download
        site['active_minutes'] += source['active_minutes']
        site['connections'] += connections
        site['connection_minutes'] += connections
        site['last_seen_ms'] = max(site['last_seen_ms'], source['last_seen_ms'])
        site['source_count'] += 1

    result = []
    for node in nodes.values():
        for site in node['sites']:
            connection_mode = int(site['total']) <= 0 and int(site['connections']) > 0
            metric_key = 'connections' if connection_mode else 'total'
            site['sources'].sort(
                key=lambda item: (int(item[metric_key]), int(item['last_seen_ms'])),
                reverse=True,
            )
            top = site['sources'][0]
            site['top_ip'] = top['source_ip']
            site['top_ip_total'] = int(top[metric_key])
            metric_total = int(site[metric_key])
            site['top_ip_share'] = (top[metric_key] / metric_total) if metric_total else 0
            site['top_ip_last_seen_ms'] = int(top['last_seen_ms'])
            site['top_sources'] = site['sources'][:5]
            site['metric_mode'] = 'connections' if connection_mode else 'traffic'
            site.pop('sources', None)
        def node_metric(site):
            return int(site['connections']) if site['metric_mode'] == 'connections' else int(site['total'])

        node['sites'].sort(key=node_metric, reverse=True)
        node['sites'] = [
            site for site in node['sites']
            if int(site['total']) > 0 or int(site['connections']) > 0
        ][:200]
        node['site_count'] = len(node['sites'])
        if node['sites']:
            result.append(node)
    result.sort(
        key=lambda item: sum(
            int(site['connections']) if site['metric_mode'] == 'connections' else int(site['total'])
            for site in item['sites']
        ),
        reverse=True,
    )
    return result


def ip_sites(hours: int, node_id: str, ip: str) -> dict:
    end_ms = now_ms()
    start_ms = end_ms - hours * 60 * 60 * 1000
    active_cutoff_ms = end_ms - ONLINE_WINDOW_SECONDS * 1000
    conn = db_connect()
    try:
        rows = conn.execute(
            '''
            SELECT site,
                   SUM(up_bytes) AS up_bytes,
                   SUM(down_bytes) AS down_bytes,
                   COUNT(*) AS active_minutes,
                   SUM(connections) AS connections,
                   MAX(last_seen_ms) AS last_seen_ms
            FROM site_minute_agg
            WHERE node_id = ? AND source_ip = ? AND minute_ms >= ?
            GROUP BY site
            ORDER BY SUM(up_bytes + down_bytes) DESC
            LIMIT 500
            ''',
            (node_id, ip, start_ms),
        ).fetchall()
    finally:
        conn.close()
    sites = []
    for row in rows:
        if is_noise_site(row['site']):
            continue
        upload = int(row['up_bytes'])
        download = int(row['down_bytes'])
        total = upload + download
        connections = int(row['connections'])
        if total <= 0 and connections <= 0:
            continue
        sites.append({
            'site': row['site'],
            'active': int(row['last_seen_ms']) >= active_cutoff_ms,
            'upload': upload,
            'download': download,
            'total': total,
            'active_minutes': int(row['active_minutes']),
            'connections': connections,
            'connection_minutes': connections,
            'last_seen_ms': int(row['last_seen_ms']),
            'metric_mode': 'connections' if total <= 0 else 'traffic',
        })
    sites.sort(
        key=lambda item: (
            not item['active'],
            -int(item['connections']) if item['metric_mode'] == 'connections' else -int(item['total']),
            -int(item['last_seen_ms']),
        )
    )
    return {
        'hours': hours,
        'node_id': node_id,
        'source_ip': ip,
        'active_window_seconds': ONLINE_WINDOW_SECONDS,
        'site_count': len(sites),
        'sites': sites,
    }


def summary(hours: int) -> dict:
    end_ms = now_ms()
    start_ms = end_ms - hours * 60 * 60 * 1000
    online_cutoff_ms = end_ms - ONLINE_WINDOW_SECONDS * 1000
    conn = db_connect()
    try:
        node_rows = {
            row['node_id']: row
            for row in conn.execute(
                'SELECT node_id, node_name, metric_mode, first_seen_ms, last_seen_ms FROM nodes'
            )
        }
        rows = conn.execute(
            '''
            SELECT node_id, source_ip,
                   SUM(up_bytes) AS up_bytes,
                   SUM(down_bytes) AS down_bytes,
                   COUNT(*) AS active_minutes,
                   SUM(connections) AS connections,
                   MIN(minute_ms) AS first_seen_ms,
                   MAX(last_seen_ms) AS last_seen_ms
            FROM minute_agg
            WHERE minute_ms >= ?
            GROUP BY node_id, source_ip
            ORDER BY SUM(up_bytes + down_bytes) DESC
            LIMIT 500
            ''',
            (start_ms,),
        ).fetchall()
        activity = activity_by_node(conn, start_ms)
        node_maps = {
            node_id: manual_device_map(conn, node_id)
            for node_id in {row['node_id'] for row in rows}
        }
        sources_by_node: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            ip = row['source_ip']
            geo = lookup_geo(conn, ip)
            source = {
                'source_ip': ip,
                'upload': int(row['up_bytes']),
                'download': int(row['down_bytes']),
                'total': int(row['up_bytes']) + int(row['down_bytes']),
                'active_minutes': int(row['active_minutes']),
                'connections': int(row['connections']),
                'connection_minutes': int(row['connections']),
                'first_seen_ms': int(row['first_seen_ms']),
                'last_seen_ms': int(row['last_seen_ms']),
                'online': int(row['last_seen_ms']) >= online_cutoff_ms,
                **geo,
            }
            sources_by_node[row['node_id']].append(source)
    finally:
        conn.close()

    nodes: dict[str, dict] = {}
    for node_id, node_sources in sources_by_node.items():
        meta = node_rows.get(node_id)
        manual_map = node_maps.get(node_id, {})
        manual_groups: dict[str, list[dict]] = defaultdict(list)
        manual_labels: dict[str, str] = {}
        unassigned: list[dict] = []
        for source in node_sources:
            manual = manual_map.get(source['source_ip'])
            if manual:
                manual_groups[manual['device_id']].append(source)
                manual_labels[manual['device_id']] = manual['label']
            else:
                unassigned.append(source)

        devices: list[dict] = []
        for device_id, device_sources in manual_groups.items():
            devices.append(make_device(
                node_id, device_id, manual_labels.get(device_id, '手动设备'),
                True, 'manual', device_sources,
            ))
        node_activity = activity.get(node_id, {})
        for cluster_sources, confidence in auto_clusters(unassigned, node_activity):
            if not cluster_sources:
                continue
            ordered_ips = sorted(item['source_ip'] for item in cluster_sources)
            digest = hashlib.sha1(
                ('|'.join(ordered_ips) + '|' + node_id).encode('utf-8')
            ).hexdigest()[:16]
            devices.append(make_device(
                node_id, 'auto:' + digest, '', False, confidence, cluster_sources,
            ))

        device_metric = 'connections' if meta and meta['metric_mode'] == 'connections' else 'total'
        devices.sort(key=lambda item: int(item[device_metric]), reverse=True)
        for index, device in enumerate(devices, start=1):
            if not device['manual']:
                device['label'] = '疑似设备 ' + str(index)
                for source in device['ips']:
                    source['device_label'] = device['label']
            device['rank'] = index
        node_sources.sort(key=lambda item: int(item[device_metric]), reverse=True)
        nodes[node_id] = {
            'node_id': node_id,
            'node_name': meta['node_name'] if meta else node_id,
            'metric_mode': meta['metric_mode'] if meta else 'traffic',
            'upload': sum(int(item['upload']) for item in node_sources),
            'download': sum(int(item['download']) for item in node_sources),
            'total': sum(int(item['total']) for item in node_sources),
            'connections': sum(int(item['connections']) for item in node_sources),
            'source_count': len(node_sources),
            'device_count': len(devices),
            'online_source_count': sum(1 for item in node_sources if item.get('online')),
            'online_device_count': sum(1 for item in devices if item.get('online')),
            'sources': node_sources,
            'devices': devices,
        }

    ordered = sorted(
        nodes.values(),
        key=lambda item: int(item['connections'])
        if item.get('metric_mode') == 'connections'
        else int(item['total']),
        reverse=True,
    )
    return {
        'hours': hours,
        'window_start_ms': start_ms,
        'window_end_ms': end_ms,
        'generated_at_ms': end_ms,
        'online_window_seconds': ONLINE_WINDOW_SECONDS,
        'nodes': ordered,
        'site_nodes': site_summary(hours),
    }


def timeline_bucket_ms(hours: int) -> int:
    if hours <= 2:
        return 5 * 60 * 1000
    if hours <= 12:
        return 15 * 60 * 1000
    if hours <= 48:
        return 60 * 60 * 1000
    if hours <= 168:
        return 6 * 60 * 60 * 1000
    return 24 * 60 * 60 * 1000


def timeline(hours: int, node_id: str, ips: list[str]) -> dict:
    end_ms = now_ms()
    start_ms = end_ms - hours * 60 * 60 * 1000
    bucket_ms = timeline_bucket_ms(hours)
    placeholders = ','.join('?' for _ in ips)
    params = [bucket_ms, node_id, *ips, start_ms]
    conn = db_connect()
    try:
        rows = conn.execute(
            f'''
            SELECT (minute_ms - (minute_ms % ?)) AS bucket_ms,
                   SUM(up_bytes) AS up_bytes,
                   SUM(down_bytes) AS down_bytes,
                   SUM(connections) AS connections,
                   COUNT(*) AS active_minutes
            FROM minute_agg
            WHERE node_id = ? AND source_ip IN ({placeholders}) AND minute_ms >= ?
            GROUP BY bucket_ms
            ORDER BY bucket_ms
            ''',
            params,
        ).fetchall()
    finally:
        conn.close()
    buckets = [
        {
            'bucket_ms': int(row['bucket_ms']),
            'upload': int(row['up_bytes']),
            'download': int(row['down_bytes']),
            'total': int(row['up_bytes']) + int(row['down_bytes']),
            'active_minutes': int(row['active_minutes']),
            'connections': int(row['connections']),
        }
        for row in rows
    ]
    return {
        'hours': hours,
        'node_id': node_id,
        'ips': ips,
        'source_ip': ips[0] if ips else '',
        'bucket_ms': bucket_ms,
        'window_start_ms': start_ms,
        'window_end_ms': end_ms,
        'buckets': buckets,
    }


def save_device_map(node_id: str, label: str, ips: list[str], device_id: str | None = None) -> str:
    if not NODE_ID_RE.fullmatch(node_id):
        raise ValueError('invalid node_id')
    label = label.strip()
    if not label:
        label = '手动设备'
    if len(label) > 80 or any(ord(char) < 32 for char in label):
        raise ValueError('invalid device label')
    if device_id:
        if not re.fullmatch(r'[A-Za-z0-9._:-]{1,80}', device_id):
            raise ValueError('invalid device_id')
    else:
        device_id = 'manual:' + uuid.uuid4().hex
    conn = db_connect()
    try:
        with conn:
            conn.executemany(
                '''INSERT INTO device_ip_map(
                       node_id, source_ip, device_id, device_label, updated_at_ms
                   ) VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(node_id, source_ip) DO UPDATE SET
                       device_id=excluded.device_id,
                       device_label=excluded.device_label,
                       updated_at_ms=excluded.updated_at_ms''',
                [(node_id, ip, device_id, label, now_ms()) for ip in ips],
            )
    finally:
        conn.close()
    return device_id


def reset_device_map(node_id: str, ips: list[str]) -> int:
    if not NODE_ID_RE.fullmatch(node_id):
        raise ValueError('invalid node_id')
    conn = db_connect()
    try:
        with conn:
            cursor = conn.executemany(
                'DELETE FROM device_ip_map WHERE node_id = ? AND source_ip = ?',
                [(node_id, ip) for ip in ips],
            )
        return cursor.rowcount
    finally:
        conn.close()


def health() -> dict:
    conn = db_connect()
    try:
        row = conn.execute(
            'SELECT COUNT(*) AS rows, COALESCE(MAX(updated_at_ms), 0) AS last_ingest_ms FROM minute_agg'
        ).fetchone()
    finally:
        conn.close()
    return {
        'ok': True,
        'db': str(DB_PATH),
        'rows': int(row['rows']),
        'last_ingest_ms': int(row['last_ingest_ms']),
        'retention_days': RETENTION_DAYS,
        'now_ms': now_ms(),
    }


def _clean_text(
    value: object,
    field: str,
    maximum: int = 255,
    required: bool = False,
) -> str:
    if value is None:
        text = ''
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value).strip()
    else:
        raise ValueError(f'invalid {field}')
    if len(text) > maximum:
        raise ValueError(f'{field} is too long')
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f'invalid {field}')
    if required and not text:
        raise ValueError(f'{field} is required')
    return text


def _safe_server(value: object) -> str:
    server = _clean_text(value, 'server', 253, True)
    if server.startswith('[') and server.endswith(']'):
        server = server[1:-1]
    try:
        return ipaddress.ip_address(server).compressed
    except ValueError:
        pass
    if not re.fullmatch(
        r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',
        server,
    ):
        raise ValueError('invalid server')
    return server


def _safe_port(value: object) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('invalid port') from exc
    if port < 1 or port > 65535:
        raise ValueError('port is out of range')
    return port


def _safe_url(value: object, field: str = 'base_url') -> str:
    text = _clean_text(value, field, 512)
    if not text:
        return ''
    parsed = urlsplit(text)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError(f'{field} must be an http(s) URL')
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(f'{field} must not contain credentials, query or fragment')
    try:
        if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
            raise ValueError
    except ValueError as exc:
        raise ValueError(f'{field} has an invalid port') from exc
    return text.rstrip('/')


def _decode_base64(value: str) -> str:
    compact = re.sub(r'\s+', '', value)
    compact += '=' * ((4 - len(compact) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(compact.encode('ascii')).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError('invalid base64 payload') from exc


def _parse_extra(value: object) -> dict:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError('extra must be a JSON object') from exc
    if not isinstance(value, dict):
        raise ValueError('extra must be an object')
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if len(encoded) > 16384:
        raise ValueError('extra is too large')
    return value


def _normalize_subscription_node(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError('node must be an object')
    protocol = _clean_text(payload.get('protocol'), 'protocol', 24, True).lower()
    if protocol == 'shadowsocks':
        protocol = 'ss'
    if protocol == 'hy2':
        protocol = 'hysteria2'
    if protocol not in SUBSCRIPTION_PROTOCOLS:
        raise ValueError('unsupported protocol')
    name = _clean_text(payload.get('name'), 'name', 120)
    server = _safe_server(payload.get('server'))
    if not name:
        name = protocol.upper() + ' · ' + server
    port = _safe_port(payload.get('port'))
    user_id = _clean_text(payload.get('user_id'), 'user_id', 160)
    password = _clean_text(payload.get('password'), 'password', 512)
    flow = _clean_text(payload.get('flow'), 'flow', 64)
    security = _clean_text(payload.get('security'), 'security', 16).lower()
    if security not in ('', 'none', 'tls', 'reality'):
        raise ValueError('unsupported security')
    sni = _clean_text(payload.get('sni'), 'sni', 253)
    fingerprint = _clean_text(payload.get('fingerprint'), 'fingerprint', 32)
    public_key = _clean_text(payload.get('public_key'), 'public_key', 256)
    short_id = _clean_text(payload.get('short_id'), 'short_id', 32)
    network = _clean_text(payload.get('network'), 'network', 16).lower()
    if network and network not in ('tcp', 'ws', 'grpc', 'http', 'h2', 'quic'):
        raise ValueError('unsupported network')
    host = _clean_text(payload.get('host'), 'host', 253)
    path = _clean_text(payload.get('path'), 'path', 512)
    service_name = _clean_text(payload.get('service_name'), 'service_name', 200)
    share_link = _clean_text(payload.get('share_link'), 'share_link', 8192)
    external_key = _clean_text(payload.get('external_key'), 'external_key', 240) or None
    origin_node_id = _clean_text(payload.get('origin_node_id'), 'origin_node_id', 64)
    extra = _parse_extra(payload.get('extra'))
    for source, target in (
        ('alter_id', 'alter_id'),
        ('scy', 'scy'),
        ('method', 'method'),
        ('alpn', 'alpn'),
        ('allow_insecure', 'allow_insecure'),
        ('skip_cert_verify', 'skip_cert_verify'),
        ('obfs', 'obfs'),
        ('obfs_password', 'obfs_password'),
        ('congestion_control', 'congestion_control'),
        ('udp_relay_mode', 'udp_relay_mode'),
        ('header_type', 'header_type'),
    ):
        if source in payload and payload.get(source) not in (None, ''):
            extra[target] = payload[source]
    if protocol == 'vless':
        if not user_id:
            raise ValueError('vless requires user_id')
        if not network:
            network = 'tcp'
    elif protocol == 'vmess':
        if not user_id:
            raise ValueError('vmess requires user_id')
        if not network:
            network = 'tcp'
    elif protocol in ('trojan', 'hysteria2', 'anytls'):
        if not password:
            raise ValueError(f'{protocol} requires password')
    elif protocol == 'ss':
        if not password or not str(extra.get('method') or '').strip():
            raise ValueError('ss requires method and password')
    elif protocol == 'tuic':
        if not user_id or not password:
            raise ValueError('tuic requires user_id and password')
    elif protocol == 'raw':
        if not share_link:
            raise ValueError('raw protocol requires share_link')
    if protocol in ('hysteria2', 'tuic', 'anytls') and not security:
        security = 'tls'
    if security == 'reality':
        if not sni or not public_key:
            raise ValueError('reality requires sni and public_key')
        if short_id and (
            len(short_id) % 2 != 0 or
            not re.fullmatch(r'[0-9a-fA-F]{0,16}', short_id)
        ):
            raise ValueError('invalid reality short_id')
        if not fingerprint:
            fingerprint = 'chrome'
        if not network:
            network = 'tcp'
    elif security == 'tls' and not fingerprint and protocol in ('vless', 'trojan', 'vmess'):
        fingerprint = 'chrome'
    record = {
        'name': name,
        'protocol': protocol,
        'server': server,
        'port': port,
        'user_id': user_id,
        'password': password,
        'flow': flow,
        'security': security,
        'sni': sni,
        'fingerprint': fingerprint,
        'public_key': public_key,
        'short_id': short_id,
        'network': network,
        'host': host,
        'path': path,
        'service_name': service_name,
        'extra': extra,
        'share_link': share_link,
        'enabled': 1 if payload.get('enabled', True) else 0,
        'external_key': external_key,
        'origin_node_id': origin_node_id,
    }
    record['share_link'] = _node_uri(record)
    return record


def _node_from_row(row: sqlite3.Row) -> dict:
    try:
        extra = json.loads(row['extra_json'] or '{}')
    except json.JSONDecodeError:
        extra = {}
    node = {
        'id': row['id'],
        'name': row['name'],
        'protocol': row['protocol'],
        'server': row['server'],
        'port': int(row['port']),
        'user_id': row['user_id'],
        'password': row['password'],
        'flow': row['flow'],
        'security': row['security'],
        'sni': row['sni'],
        'fingerprint': row['fingerprint'],
        'public_key': row['public_key'],
        'short_id': row['short_id'],
        'network': row['network'],
        'host': row['host'],
        'path': row['path'],
        'service_name': row['service_name'],
        'extra': extra if isinstance(extra, dict) else {},
        'share_link': row['share_link'],
        'enabled': bool(row['enabled']),
        'external_key': row['external_key'] or '',
        'origin_node_id': row['origin_node_id'],
        'created_at_ms': int(row['created_at_ms']),
        'updated_at_ms': int(row['updated_at_ms']),
    }
    node['uri'] = node['share_link'] or _node_uri(node)
    return node


def save_subscription_node(payload: object) -> dict:
    record = _normalize_subscription_node(payload)
    node_id = _clean_text(
        payload.get('id') if isinstance(payload, dict) else '',
        'id',
        64,
    )
    if node_id and not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', node_id):
        raise ValueError('invalid node id')
    timestamp = now_ms()
    conn = db_connect()
    try:
        existing = None
        if node_id:
            existing = conn.execute(
                'SELECT * FROM subscription_nodes WHERE id = ?', (node_id,)
            ).fetchone()
        if existing is None and record['external_key']:
            existing = conn.execute(
                'SELECT * FROM subscription_nodes WHERE external_key = ?',
                (record['external_key'],),
            ).fetchone()
        if existing is not None:
            node_id = existing['id']
            created_at = int(existing['created_at_ms'])
        else:
            node_id = node_id or uuid.uuid4().hex
            created_at = timestamp
        with conn:
            conn.execute(
                '''
                INSERT INTO subscription_nodes(
                    id, name, protocol, server, port, user_id, password, flow,
                    security, sni, fingerprint, public_key, short_id, network,
                    host, path, service_name, extra_json, share_link, enabled,
                    external_key, origin_node_id, created_at_ms, updated_at_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    protocol=excluded.protocol,
                    server=excluded.server,
                    port=excluded.port,
                    user_id=excluded.user_id,
                    password=excluded.password,
                    flow=excluded.flow,
                    security=excluded.security,
                    sni=excluded.sni,
                    fingerprint=excluded.fingerprint,
                    public_key=excluded.public_key,
                    short_id=excluded.short_id,
                    network=excluded.network,
                    host=excluded.host,
                    path=excluded.path,
                    service_name=excluded.service_name,
                    extra_json=excluded.extra_json,
                    share_link=excluded.share_link,
                    enabled=excluded.enabled,
                    external_key=excluded.external_key,
                    origin_node_id=excluded.origin_node_id,
                    updated_at_ms=excluded.updated_at_ms
                ''',
                (
                    node_id, record['name'], record['protocol'], record['server'],
                    record['port'], record['user_id'], record['password'], record['flow'],
                    record['security'], record['sni'], record['fingerprint'],
                    record['public_key'], record['short_id'], record['network'],
                    record['host'], record['path'], record['service_name'],
                    json.dumps(record['extra'], ensure_ascii=False, separators=(',', ':')),
                    record['share_link'], record['enabled'], record['external_key'],
                    record['origin_node_id'], created_at, timestamp,
                ),
            )
        row = conn.execute(
            'SELECT * FROM subscription_nodes WHERE id = ?', (node_id,)
        ).fetchone()
        return _node_from_row(row)
    finally:
        conn.close()


def delete_subscription_node(node_id: str) -> bool:
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', node_id):
        raise ValueError('invalid node id')
    conn = db_connect()
    try:
        with conn:
            conn.execute('DELETE FROM subscription_node_map WHERE node_id = ?', (node_id,))
            cursor = conn.execute('DELETE FROM subscription_nodes WHERE id = ?', (node_id,))
        return cursor.rowcount > 0
    finally:
        conn.close()


def list_subscription_nodes() -> list[dict]:
    conn = db_connect()
    try:
        rows = conn.execute(
            'SELECT * FROM subscription_nodes ORDER BY updated_at_ms DESC, name ASC'
        ).fetchall()
        return [_node_from_row(row) for row in rows]
    finally:
        conn.close()


def _uri_host(server: str) -> str:
    return '[' + server + ']' if ':' in server and not server.startswith('[') else server


def _query_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def _extra_alpn(extra: dict) -> str:
    value = extra.get('alpn')
    if isinstance(value, list):
        return ','.join(str(item).strip() for item in value if str(item).strip())
    return str(value or '').strip()


def _node_uri(node: dict) -> str:
    protocol = str(node.get('protocol') or '').lower()
    if protocol == 'raw':
        return str(node.get('share_link') or '')
    if not protocol:
        return ''
    host = _uri_host(str(node.get('server') or ''))
    port = int(node.get('port') or 0)
    name = str(node.get('name') or protocol)
    extra = node.get('extra') if isinstance(node.get('extra'), dict) else {}
    security = str(node.get('security') or '')
    network = str(node.get('network') or 'tcp')
    sni = str(node.get('sni') or '')
    fingerprint = str(node.get('fingerprint') or '')
    flow = str(node.get('flow') or '')
    fragment = '#' + quote(name, safe='')
    if protocol == 'vless':
        params = [('encryption', 'none'), ('security', security or 'none'), ('type', network)]
        if sni:
            params.append(('sni', sni))
        if fingerprint:
            params.append(('fp', fingerprint))
        if flow:
            params.append(('flow', flow))
        if security == 'reality':
            params.append(('pbk', str(node.get('public_key') or '')))
            if node.get('short_id'):
                params.append(('sid', str(node.get('short_id'))))
        if network == 'ws':
            params.append(('path', str(node.get('path') or '/')))
            if node.get('host'):
                params.append(('host', str(node['host'])))
        elif network == 'grpc':
            params.append(('serviceName', str(node.get('service_name') or '')))
        alpn = _extra_alpn(extra)
        if alpn:
            params.append(('alpn', alpn))
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            params.append(('allowInsecure', '1'))
        query = '&'.join(f'{quote(str(key), safe="")}={quote(str(value), safe="")}' for key, value in params)
        return f'vless://{quote(str(node.get("user_id") or ""), safe="")}@{host}:{port}?{query}{fragment}'
    if protocol == 'vmess':
        payload = {
            'v': '2',
            'ps': name,
            'add': str(node.get('server') or ''),
            'port': str(port),
            'id': str(node.get('user_id') or ''),
            'aid': str(extra.get('alter_id') or 0),
            'scy': str(extra.get('scy') or 'auto'),
            'net': network,
            'type': str(extra.get('header_type') or 'none'),
            'host': str(node.get('host') or ''),
            'path': str(node.get('path') or ''),
            'tls': 'tls' if security in ('tls', 'reality') else '',
            'sni': sni,
            'fp': fingerprint,
            'alpn': _extra_alpn(extra),
        }
        encoded = base64.b64encode(
            json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        ).decode('ascii')
        return 'vmess://' + encoded
    if protocol == 'trojan':
        params = [('security', security or 'tls'), ('type', network)]
        if sni:
            params.append(('sni', sni))
        if fingerprint:
            params.append(('fp', fingerprint))
        if network == 'ws':
            params.append(('path', str(node.get('path') or '/')))
            if node.get('host'):
                params.append(('host', str(node['host'])))
        elif network == 'grpc':
            params.append(('serviceName', str(node.get('service_name') or '')))
        alpn = _extra_alpn(extra)
        if alpn:
            params.append(('alpn', alpn))
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            params.append(('allowInsecure', '1'))
        query = '&'.join(f'{quote(str(key), safe="")}={quote(str(value), safe="")}' for key, value in params)
        return f'trojan://{quote(str(node.get("password") or ""), safe="")}@{host}:{port}?{query}{fragment}'
    if protocol == 'ss':
        method = str(extra.get('method') or '')
        userinfo = base64.urlsafe_b64encode(
            (method + ':' + str(node.get('password') or '')).encode('utf-8')
        ).decode('ascii').rstrip('=')
        return f'ss://{userinfo}@{host}:{port}{fragment}'
    if protocol == 'hysteria2':
        params = []
        if sni:
            params.append(('sni', sni))
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            params.append(('insecure', '1'))
        if extra.get('obfs'):
            params.append(('obfs', str(extra['obfs'])))
        if extra.get('obfs_password'):
            params.append(('obfs-password', str(extra['obfs_password'])))
        query = '&'.join(f'{quote(str(key), safe="")}={quote(str(value), safe="")}' for key, value in params)
        return f'hysteria2://{quote(str(node.get("password") or ""), safe="")}@{host}:{port}' + (f'?{query}' if query else '') + fragment
    if protocol == 'tuic':
        params = [('sni', sni or str(node.get('server') or ''))]
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            params.append(('allow_insecure', '1'))
        if extra.get('congestion_control'):
            params.append(('congestion_control', str(extra['congestion_control'])))
        if extra.get('udp_relay_mode'):
            params.append(('udp_relay_mode', str(extra['udp_relay_mode'])))
        alpn = _extra_alpn(extra)
        if alpn:
            params.append(('alpn', alpn))
        query = '&'.join(f'{quote(str(key), safe="")}={quote(str(value), safe="")}' for key, value in params)
        user = quote(str(node.get('user_id') or ''), safe='')
        password = quote(str(node.get('password') or ''), safe='')
        return f'tuic://{user}:{password}@{host}:{port}?{query}{fragment}'
    if protocol == 'anytls':
        params = [('security', 'tls')]
        if sni:
            params.append(('sni', sni))
        if fingerprint:
            params.append(('fp', fingerprint))
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            params.append(('allowInsecure', '1'))
        alpn = _extra_alpn(extra)
        if alpn:
            params.append(('alpn', alpn))
        query = '&'.join(f'{quote(str(key), safe="")}={quote(str(value), safe="")}' for key, value in params)
        return f'anytls://{quote(str(node.get("password") or ""), safe="")}@{host}:{port}?{query}{fragment}'
    return str(node.get('share_link') or '')


def _unique_node_names(nodes: list[dict]) -> list[tuple[dict, str]]:
    used: dict[str, int] = {
        'PROXY': 1, 'DIRECT': 1, 'REJECT': 1, 'GLOBAL': 1, 'direct': 1,
    }
    result: list[tuple[dict, str]] = []
    for node in nodes:
        base = str(node.get('name') or node.get('protocol') or 'node').strip() or 'node'
        count = used.get(base, 0) + 1
        used[base] = count
        name = base if count == 1 else f'{base} {count}'
        result.append((node, name))
    return result


def _clash_proxy(node: dict, name: str) -> dict:
    protocol = str(node.get('protocol') or '').lower()
    if protocol == 'raw':
        raise ValueError('raw 节点只能用于 base64 / links 订阅')
    extra = node.get('extra') if isinstance(node.get('extra'), dict) else {}
    security = str(node.get('security') or '')
    network = str(node.get('network') or 'tcp')
    proxy = {
        'name': name,
        'type': protocol,
        'server': node['server'],
        'port': int(node['port']),
        'udp': bool(extra.get('udp', True)),
    }
    if protocol == 'ss':
        proxy['type'] = 'ss'
        proxy['cipher'] = str(extra.get('method') or '')
        proxy['password'] = node['password']
        return proxy
    if protocol == 'vmess':
        proxy['uuid'] = node['user_id']
        proxy['alterId'] = int(extra.get('alter_id') or 0)
        proxy['cipher'] = str(extra.get('scy') or 'auto')
    elif protocol == 'vless':
        proxy['uuid'] = node['user_id']
        if node.get('flow'):
            proxy['flow'] = node['flow']
    elif protocol == 'trojan':
        proxy['password'] = node['password']
    elif protocol == 'hysteria2':
        proxy['password'] = node['password']
    elif protocol == 'tuic':
        proxy['uuid'] = node['user_id']
        proxy['password'] = node['password']
        proxy['congestion-controller'] = str(extra.get('congestion_control') or 'bbr')
        proxy['udp-relay-mode'] = str(extra.get('udp_relay_mode') or 'native')
    elif protocol == 'anytls':
        proxy['password'] = node['password']
    if network and protocol in ('vless', 'vmess', 'trojan'):
        proxy['network'] = network
    if node.get('sni'):
        proxy['sni'] = node['sni']
    if node.get('fingerprint'):
        proxy['client-fingerprint'] = node['fingerprint']
    if security in ('tls', 'reality') and protocol in ('vless', 'vmess', 'trojan'):
        proxy['tls'] = True
        if node.get('sni'):
            proxy['servername'] = node['sni']
    if security == 'reality':
        proxy['reality-opts'] = {
            'public-key': node.get('public_key') or '',
            'short-id': node.get('short_id') or '',
        }
    if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
        proxy['skip-cert-verify'] = True
    alpn = _extra_alpn(extra)
    if alpn:
        proxy['alpn'] = [item for item in alpn.split(',') if item]
    if network == 'ws':
        proxy['ws-opts'] = {
            'path': node.get('path') or '/',
            'headers': {'Host': node['host']} if node.get('host') else {},
        }
    elif network == 'grpc':
        proxy['grpc-opts'] = {'grpc-service-name': node.get('service_name') or ''}
    elif network in ('http', 'h2'):
        proxy['h2-opts'] = {
            'path': node.get('path') or '/',
            'host': [node['host']] if node.get('host') else [],
        }
    if protocol == 'hysteria2':
        if extra.get('obfs'):
            proxy['obfs'] = str(extra['obfs'])
        if extra.get('obfs_password'):
            proxy['obfs-password'] = str(extra['obfs_password'])
    if extra.get('dialer_proxy'):
        proxy['dialer-proxy'] = str(extra['dialer_proxy'])
    return proxy


def _clash_profile(nodes: list[dict]) -> str:
    named = _unique_node_names(nodes)
    proxies = [_clash_proxy(node, name) for node, name in named]
    names = [name for _, name in named]
    profile = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'proxies': proxies,
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': names + ['DIRECT']},
        ],
        'rules': ['MATCH,PROXY'],
    }
    if yaml is not None:
        return yaml.safe_dump(
            profile, allow_unicode=True, sort_keys=False, width=1000,
        )
    return json.dumps(profile, ensure_ascii=False, indent=2) + '\n'


def _singbox_transport(node: dict) -> dict | None:
    network = str(node.get('network') or 'tcp')
    if network == 'ws':
        headers = {'Host': node['host']} if node.get('host') else {}
        return {'type': 'ws', 'path': node.get('path') or '/', 'headers': headers}
    if network == 'grpc':
        return {'type': 'grpc', 'service_name': node.get('service_name') or ''}
    if network in ('http', 'h2'):
        return {
            'type': 'http',
            'path': node.get('path') or '/',
            'host': [node['host']] if node.get('host') else [],
        }
    if network == 'quic':
        return {'type': 'quic'}
    return None


def _singbox_outbound(node: dict, tag: str) -> dict:
    protocol = str(node.get('protocol') or '').lower()
    if protocol == 'raw':
        raise ValueError('raw 节点只能用于 base64 / links 订阅')
    extra = node.get('extra') if isinstance(node.get('extra'), dict) else {}
    security = str(node.get('security') or '')
    outbound_type = 'shadowsocks' if protocol == 'ss' else protocol
    outbound: dict = {
        'type': outbound_type,
        'tag': tag,
        'server': node['server'],
        'server_port': int(node['port']),
    }
    if protocol == 'vless':
        outbound.update({'uuid': node['user_id'], 'packet_encoding': 'xudp'})
        if node.get('flow'):
            outbound['flow'] = node['flow']
    elif protocol == 'vmess':
        outbound.update({
            'uuid': node['user_id'],
            'security': str(extra.get('scy') or 'auto'),
            'alter_id': int(extra.get('alter_id') or 0),
        })
    elif protocol in ('trojan', 'hysteria2', 'anytls'):
        outbound['password'] = node['password']
    elif protocol == 'ss':
        outbound.update({
            'method': str(extra.get('method') or ''),
            'password': node['password'],
        })
    elif protocol == 'tuic':
        outbound.update({
            'uuid': node['user_id'],
            'password': node['password'],
            'congestion_control': str(extra.get('congestion_control') or 'bbr'),
            'udp_relay_mode': str(extra.get('udp_relay_mode') or 'native'),
        })
    if security in ('tls', 'reality'):
        tls = {
            'enabled': True,
            'server_name': node.get('sni') or node['server'],
        }
        if _query_truthy(extra.get('allow_insecure') or extra.get('skip_cert_verify')):
            tls['insecure'] = True
        if node.get('fingerprint') and protocol in ('vless', 'trojan', 'vmess', 'anytls'):
            tls['utls'] = {'enabled': True, 'fingerprint': node['fingerprint']}
        if security == 'reality':
            tls['reality'] = {
                'enabled': True,
                'public_key': node.get('public_key') or '',
                'short_id': node.get('short_id') or '',
            }
        alpn = _extra_alpn(extra)
        if alpn:
            tls['alpn'] = [item for item in alpn.split(',') if item]
        outbound['tls'] = tls
    transport = _singbox_transport(node)
    if transport is not None:
        outbound['transport'] = transport
    if protocol == 'hysteria2':
        if extra.get('obfs'):
            outbound['obfs'] = {
                'type': str(extra['obfs']),
                'password': str(extra.get('obfs_password') or ''),
            }
    return outbound


def _singbox_profile(nodes: list[dict]) -> str:
    named = _unique_node_names(nodes)
    name_to_tag = {str(node.get('name') or ''): name for node, name in named}
    outbounds = []
    for node, name in named:
        outbound = _singbox_outbound(node, name)
        extra = node.get('extra') if isinstance(node.get('extra'), dict) else {}
        dialer = str(extra.get('dialer_proxy') or '').strip()
        if dialer and dialer in name_to_tag:
            outbound['detour'] = name_to_tag[dialer]
        outbounds.append(outbound)
    outbounds.append({
        'type': 'selector',
        'tag': 'PROXY',
        'outbounds': [name for _, name in named] + ['direct'],
    })
    outbounds.append({'type': 'direct', 'tag': 'direct'})
    profile = {
        'log': {'level': 'info'},
        'inbounds': [{
            'type': 'mixed',
            'tag': 'mixed-in',
            'listen': '127.0.0.1',
            'listen_port': 2080,
        }],
        'outbounds': outbounds,
        'route': {'final': 'PROXY'},
    }
    return json.dumps(profile, ensure_ascii=False, indent=2) + '\n'


def _subscription_links(nodes: list[dict]) -> str:
    return '\n'.join(_node_uri(node) for node in nodes)


def _subscription_from_row(row: sqlite3.Row, node_ids: list[str] | None = None) -> dict:
    result = {
        'id': row['id'],
        'name': row['name'],
        'token': row['token'],
        'short_code': row['short_code'],
        'base_url': row['base_url'],
        'format': row['format'],
        'include_all': bool(row['include_all']),
        'enabled': bool(row['enabled']),
        'created_at_ms': int(row['created_at_ms']),
        'updated_at_ms': int(row['updated_at_ms']),
    }
    if node_ids is not None:
        result['node_ids'] = node_ids
    long_base = row['base_url'] or SUB_BASE_URL
    if long_base:
        result['long_url'] = long_base.rstrip('/') + '/' + row['token']
        result['short_url'] = long_base.rstrip('/') + '/s/' + row['short_code']
    else:
        result['long_url'] = ''
        result['short_url'] = ''
    return result


def _node_ids_for_subscription(conn: sqlite3.Connection, subscription_id: str) -> list[str]:
    rows = conn.execute(
        '''SELECT node_id FROM subscription_node_map
           WHERE subscription_id = ? ORDER BY position, rowid''',
        (subscription_id,),
    ).fetchall()
    return [row['node_id'] for row in rows]


def _normalize_subscription_format(value: object) -> str:
    format_name = _clean_text(value, 'format', 16).lower() or 'auto'
    if format_name == 'mihomo':
        format_name = 'clash'
    elif format_name == 'sing-box':
        format_name = 'singbox'
    elif format_name in ('xray', 'v2ray'):
        format_name = 'base64'
    if format_name not in ('auto', 'clash', 'singbox', 'base64', 'links'):
        raise ValueError('unsupported subscription format')
    return format_name


def save_subscription(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError('subscription must be an object')
    name = _clean_text(payload.get('name'), 'name', 120, True)
    include_all = 1 if payload.get('include_all') else 0
    node_ids = payload.get('node_ids') or []
    if not isinstance(node_ids, list):
        raise ValueError('node_ids must be an array')
    if not include_all and not node_ids:
        raise ValueError('node_ids must be a non-empty array')
    normalized_ids: list[str] = []
    seen: set[str] = set()
    for value in node_ids[:200]:
        node_id = _clean_text(value, 'node_id', 64)
        if not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', node_id):
            raise ValueError('invalid node_id')
        if node_id not in seen:
            normalized_ids.append(node_id)
            seen.add(node_id)
    if not include_all and not normalized_ids:
        raise ValueError('node_ids must contain at least one node')
    base_url = _safe_url(payload.get('base_url'), 'base_url')
    format_name = _normalize_subscription_format(payload.get('format'))
    enabled = 1 if payload.get('enabled', True) else 0
    subscription_id = _clean_text(payload.get('id'), 'id', 64)
    if subscription_id and not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', subscription_id):
        raise ValueError('invalid subscription id')
    timestamp = now_ms()
    conn = db_connect()
    try:
        existing = None
        if subscription_id:
            existing = conn.execute(
                'SELECT * FROM subscriptions WHERE id = ?', (subscription_id,)
            ).fetchone()
        if existing is None:
            subscription_id = subscription_id or uuid.uuid4().hex
            token = secrets.token_urlsafe(32)
            short_code = secrets.token_urlsafe(8)
            while conn.execute(
                'SELECT 1 FROM subscriptions WHERE token = ? OR short_code = ?',
                (token, short_code),
            ).fetchone():
                token = secrets.token_urlsafe(32)
                short_code = secrets.token_urlsafe(8)
            created_at = timestamp
        else:
            token = existing['token']
            short_code = existing['short_code']
            created_at = int(existing['created_at_ms'])
        placeholders = ','.join('?' for _ in normalized_ids)
        found = {
            row['id'] for row in conn.execute(
                f'SELECT id FROM subscription_nodes WHERE id IN ({placeholders})',
                normalized_ids,
            )
        }
        missing = [node_id for node_id in normalized_ids if node_id not in found]
        if missing:
            if include_all:
                normalized_ids = [node_id for node_id in normalized_ids if node_id in found]
            else:
                raise ValueError('subscription contains unknown node ids')
        with conn:
            conn.execute(
                '''INSERT INTO subscriptions(
                       id, name, token, short_code, base_url, format, include_all, enabled,
                       created_at_ms, updated_at_ms
                   ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       name=excluded.name,
                       base_url=excluded.base_url,
                       format=excluded.format,
                       include_all=excluded.include_all,
                       enabled=excluded.enabled,
                       updated_at_ms=excluded.updated_at_ms''',
                (
                    subscription_id, name, token, short_code, base_url,
                    format_name, include_all, enabled, created_at, timestamp,
                ),
            )
            conn.execute(
                'DELETE FROM subscription_node_map WHERE subscription_id = ?',
                (subscription_id,),
            )
            conn.executemany(
                '''INSERT INTO subscription_node_map(subscription_id, node_id, position)
                   VALUES(?, ?, ?)''',
                [
                    (subscription_id, node_id, index)
                    for index, node_id in enumerate(normalized_ids)
                ],
            )
        row = conn.execute(
            'SELECT * FROM subscriptions WHERE id = ?', (subscription_id,)
        ).fetchone()
        return _subscription_from_row(row, normalized_ids)
    finally:
        conn.close()


def delete_subscription(subscription_id: str) -> bool:
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', subscription_id):
        raise ValueError('invalid subscription id')
    conn = db_connect()
    try:
        with conn:
            conn.execute(
                'DELETE FROM subscription_node_map WHERE subscription_id = ?',
                (subscription_id,),
            )
            cursor = conn.execute(
                'DELETE FROM subscriptions WHERE id = ?',
                (subscription_id,),
            )
        return cursor.rowcount > 0
    finally:
        conn.close()


def rotate_subscription(subscription_id: str) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', subscription_id):
        raise ValueError('invalid subscription id')
    conn = db_connect()
    try:
        existing = conn.execute(
            'SELECT * FROM subscriptions WHERE id = ?', (subscription_id,)
        ).fetchone()
        if existing is None:
            raise ValueError('subscription not found')
        token = secrets.token_urlsafe(32)
        short_code = secrets.token_urlsafe(8)
        while conn.execute(
            'SELECT 1 FROM subscriptions WHERE id != ? AND (token = ? OR short_code = ?)',
            (subscription_id, token, short_code),
        ).fetchone():
            token = secrets.token_urlsafe(32)
            short_code = secrets.token_urlsafe(8)
        timestamp = now_ms()
        with conn:
            conn.execute(
                '''UPDATE subscriptions
                   SET token = ?, short_code = ?, updated_at_ms = ?
                   WHERE id = ?''',
                (token, short_code, timestamp, subscription_id),
            )
        row = conn.execute(
            'SELECT * FROM subscriptions WHERE id = ?', (subscription_id,)
        ).fetchone()
        return _subscription_from_row(
            row, _node_ids_for_subscription(conn, subscription_id)
        )
    finally:
        conn.close()


def subscription_state() -> dict:
    conn = db_connect()
    try:
        node_rows = conn.execute(
            'SELECT * FROM subscription_nodes ORDER BY updated_at_ms DESC, name ASC'
        ).fetchall()
        nodes = [_node_from_row(row) for row in node_rows]
        rows = conn.execute(
            'SELECT * FROM subscriptions ORDER BY updated_at_ms DESC, name ASC'
        ).fetchall()
        subscriptions = [
            _subscription_from_row(
                row, _node_ids_for_subscription(conn, row['id'])
            )
            for row in rows
        ]
    finally:
        conn.close()
    return {
        'ok': True,
        'default_base_url': SUB_BASE_URL,
        'formats': ['auto', 'clash', 'singbox', 'base64', 'links'],
        'nodes': nodes,
        'subscriptions': subscriptions,
    }


def _subscription_base(row: sqlite3.Row | dict, fallback: str = '') -> str:
    if isinstance(row, sqlite3.Row):
        stored = str(row['base_url'] or '')
    else:
        stored = str(row.get('base_url') or '')
    return (stored or SUB_BASE_URL or fallback).rstrip('/')


def _subscription_public_urls(row: sqlite3.Row | dict, fallback: str = '') -> tuple[str, str]:
    base = _subscription_base(row, fallback)
    if isinstance(row, sqlite3.Row):
        token, short_code = row['token'], row['short_code']
    else:
        token, short_code = row['token'], row['short_code']
    return (
        base + '/' + token if base else '',
        base + '/s/' + short_code if base else '',
    )


def _detect_subscription_format(row: sqlite3.Row, requested: str, user_agent: str) -> str:
    fmt = _normalize_subscription_format(requested)
    if fmt != 'auto':
        return fmt
    stored = _normalize_subscription_format(row['format'])
    if stored != 'auto':
        return stored
    ua = (user_agent or '').lower()
    if 'clash' in ua or 'mihomo' in ua:
        return 'clash'
    if 'sing-box' in ua or 'singbox' in ua or 'sfa/' in ua or 'sfa ' in ua:
        return 'singbox'
    return 'base64'


def render_subscription(row: sqlite3.Row, requested_format: str, user_agent: str) -> tuple[bytes, str, str]:
    fmt = _detect_subscription_format(row, requested_format, user_agent)
    conn = db_connect()
    try:
        if row['include_all']:
            rows = conn.execute(
                '''SELECT * FROM subscription_nodes
                   WHERE enabled = 1 ORDER BY updated_at_ms DESC, name ASC'''
            ).fetchall()
            nodes = [_node_from_row(item) for item in rows]
        else:
            node_ids = _node_ids_for_subscription(conn, row['id'])
            if not node_ids:
                raise ValueError('subscription has no nodes')
            placeholders = ','.join('?' for _ in node_ids)
            rows = conn.execute(
                f'SELECT * FROM subscription_nodes WHERE id IN ({placeholders})',
                node_ids,
            ).fetchall()
            by_id = {item['id']: _node_from_row(item) for item in rows}
            nodes = [
                by_id[node_id] for node_id in node_ids
                if node_id in by_id and by_id[node_id].get('enabled')
            ]
    finally:
        conn.close()
    if not nodes:
        raise ValueError('subscription has no enabled nodes')
    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '-', row['name']).strip('-') or 'subscription'
    if fmt == 'clash':
        return _clash_profile(nodes).encode('utf-8'), 'text/yaml; charset=utf-8', safe_name + '.yaml'
    if fmt == 'singbox':
        return _singbox_profile(nodes).encode('utf-8'), 'application/json; charset=utf-8', safe_name + '.json'
    links = _subscription_links(nodes)
    if fmt == 'links':
        return links.encode('utf-8'), 'text/plain; charset=utf-8', safe_name + '.txt'
    encoded = base64.b64encode(links.encode('utf-8')).decode('ascii')
    return encoded.encode('utf-8'), 'text/plain; charset=utf-8', safe_name + '.txt'


def _parse_share_link(link: str, index: int) -> dict:
    original = link.strip()
    if not original or '://' not in original:
        raise ValueError('not a share link')
    scheme = original.split('://', 1)[0].lower()
    if scheme == 'vmess':
        raw = original.split('://', 1)[1]
        try:
            decoded = json.loads(_decode_base64(raw))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError('invalid vmess payload') from exc
        if not isinstance(decoded, dict):
            raise ValueError('invalid vmess payload')
        server = _safe_server(decoded.get('add'))
        port = _safe_port(decoded.get('port'))
        name = str(decoded.get('ps') or f'VMESS · {server}').strip()
        return {
            'name': name,
            'protocol': 'vmess',
            'server': server,
            'port': port,
            'user_id': str(decoded.get('id') or ''),
            'network': str(decoded.get('net') or 'tcp'),
            'host': str(decoded.get('host') or ''),
            'path': str(decoded.get('path') or ''),
            'sni': str(decoded.get('sni') or ''),
            'security': 'tls' if str(decoded.get('tls') or '').lower() in ('tls', 'reality') else 'none',
            'share_link': original,
            'external_key': 'link:' + hashlib.sha256(original.encode('utf-8')).hexdigest()[:32],
            'extra': {
                'alter_id': decoded.get('aid') or 0,
                'scy': decoded.get('scy') or 'auto',
                'header_type': decoded.get('type') or 'none',
                'alpn': decoded.get('alpn') or '',
            },
        }
    parsed = urlsplit(original)
    if not parsed.hostname:
        raise ValueError('share link has no server')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('share link has an invalid port') from exc
    if port is None:
        port = 443
    q = {
        key: values[0]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }
    name = unquote(parsed.fragment or '') or f'{scheme.upper()} · {parsed.hostname}'
    common = {
        'name': name,
        'server': parsed.hostname,
        'port': port,
        'network': q.get('type') or q.get('net') or 'tcp',
        'host': q.get('host') or '',
        'path': q.get('path') or '',
        'service_name': q.get('serviceName') or q.get('service_name') or '',
        'sni': q.get('sni') or q.get('peer') or '',
        'fingerprint': q.get('fp') or q.get('fingerprint') or '',
        'flow': q.get('flow') or '',
        'security': (q.get('security') or q.get('tls') or '').lower(),
        'share_link': original,
        'external_key': 'link:' + hashlib.sha256(original.encode('utf-8')).hexdigest()[:32],
        'extra': {
            'allow_insecure': _query_truthy(q.get('allowInsecure') or q.get('insecure')),
            'alpn': q.get('alpn') or '',
        },
    }
    if scheme == 'vless':
        common.update({
            'protocol': 'vless',
            'user_id': unquote(parsed.username or ''),
            'security': common['security'] or ('reality' if q.get('pbk') else 'tls'),
            'public_key': q.get('pbk') or '',
            'short_id': q.get('sid') or '',
        })
    elif scheme == 'trojan':
        common.update({
            'protocol': 'trojan',
            'password': unquote(parsed.username or ''),
            'security': common['security'] or 'tls',
        })
    elif scheme in ('hysteria2', 'hy2'):
        common.update({
            'protocol': 'hysteria2',
            'password': unquote(parsed.password or parsed.username or ''),
            'security': 'tls',
            'extra': {
                'allow_insecure': _query_truthy(q.get('insecure') or q.get('allowInsecure')),
                'obfs': q.get('obfs') or '',
                'obfs_password': q.get('obfs-password') or '',
                'alpn': q.get('alpn') or '',
            },
        })
    elif scheme == 'tuic':
        common.update({
            'protocol': 'tuic',
            'user_id': unquote(parsed.username or ''),
            'password': unquote(parsed.password or ''),
            'security': 'tls',
            'extra': {
                'allow_insecure': _query_truthy(q.get('allow_insecure') or q.get('allowInsecure')),
                'congestion_control': q.get('congestion_control') or 'bbr',
                'udp_relay_mode': q.get('udp_relay_mode') or 'native',
                'alpn': q.get('alpn') or '',
            },
        })
    elif scheme == 'anytls':
        common.update({
            'protocol': 'anytls',
            'password': unquote(parsed.username or ''),
            'security': 'tls',
        })
    elif scheme == 'ss':
        body = original[5:].split('#', 1)[0]
        if '@' in body:
            userinfo, hostport = body.rsplit('@', 1)
            decoded = _decode_base64(userinfo) if ':' not in userinfo else unquote(userinfo)
            hostport_url = urlsplit('ss://' + hostport)
            if not hostport_url.hostname:
                raise ValueError('invalid ss server')
            common['server'] = hostport_url.hostname
            common['port'] = _safe_port(hostport_url.port or 8388)
        else:
            decoded = _decode_base64(body)
        if ':' not in decoded:
            raise ValueError('invalid ss credentials')
        method, password = decoded.split(':', 1)
        common.update({
            'protocol': 'ss',
            'password': password,
            'security': 'none',
            'network': '',
            'extra': {'method': method},
        })
    else:
        common.update({
            'protocol': 'raw',
            'security': 'none',
            'network': '',
        })
    common['name'] = common['name'].strip() or f'{scheme.upper()} · {common["server"]}'
    return common


def import_subscription_links(text: object) -> dict:
    if not isinstance(text, str):
        raise ValueError('links must be text')
    lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    ]
    if not lines:
        raise ValueError('no share links found')
    if len(lines) > 300:
        raise ValueError('too many share links')
    nodes = []
    errors = []
    for index, line in enumerate(lines, start=1):
        try:
            nodes.append(save_subscription_node(_parse_share_link(line, index)))
        except ValueError as exc:
            errors.append({'line': index, 'error': str(exc)})
    return {'ok': True, 'imported': len(nodes), 'nodes': nodes, 'errors': errors}


def _proxy_to_subscription_node(proxy: object, file_meta: dict) -> dict:
    if not isinstance(proxy, dict):
        raise ValueError('proxy must be an object')
    protocol = str(proxy.get('type') or '').strip().lower()
    if protocol == 'shadowsocks':
        protocol = 'ss'
    if protocol not in ('vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'tuic', 'anytls'):
        raise ValueError('unsupported proxy type: ' + (protocol or 'unknown'))
    name = str(proxy.get('name') or '').strip()
    if not name:
        name = protocol.upper() + ' · ' + str(proxy.get('server') or '')
    server = str(proxy.get('server') or '').strip()
    port = int(proxy.get('port') or 0)
    security = 'none'
    if protocol in ('anytls', 'hysteria2', 'tuic'):
        security = 'tls'
    if proxy.get('tls'):
        security = 'tls'
    reality = proxy.get('reality-opts')
    if isinstance(reality, dict):
        security = 'reality'
    network = str(proxy.get('network') or '').strip().lower()
    if not network and protocol in ('vless', 'vmess', 'trojan'):
        network = 'tcp'
    ws = proxy.get('ws-opts') if isinstance(proxy.get('ws-opts'), dict) else {}
    ws_headers = ws.get('headers') if isinstance(ws.get('headers'), dict) else {}
    grpc = proxy.get('grpc-opts') if isinstance(proxy.get('grpc-opts'), dict) else {}
    extra: dict = {}
    alpn = proxy.get('alpn')
    if alpn:
        extra['alpn'] = alpn
    if proxy.get('udp') is not None:
        extra['udp'] = bool(proxy.get('udp'))
    if proxy.get('skip-cert-verify') is not None:
        extra['skip_cert_verify'] = bool(proxy.get('skip-cert-verify'))
        extra['allow_insecure'] = bool(proxy.get('skip-cert-verify'))
    for source, target in (
        ('dialer-proxy', 'dialer_proxy'),
        ('ip-version', 'ip_version'),
        ('client-fingerprint', 'client_fingerprint'),
        ('obfs', 'obfs'),
        ('obfs-password', 'obfs_password'),
        ('congestion-controller', 'congestion_control'),
        ('udp-relay-mode', 'udp_relay_mode'),
    ):
        if proxy.get(source) not in (None, ''):
            extra[target] = proxy.get(source)
    if protocol == 'ss':
        extra['method'] = str(proxy.get('cipher') or proxy.get('method') or '')
    elif protocol == 'vmess':
        extra['alter_id'] = proxy.get('alterId', proxy.get('alter-id', 0)) or 0
        extra['scy'] = str(proxy.get('cipher') or proxy.get('scy') or 'auto')
    elif protocol == 'tuic':
        extra.setdefault('congestion_control', 'bbr')
        extra.setdefault('udp_relay_mode', 'native')
    reality_public = ''
    reality_short = ''
    if isinstance(reality, dict):
        reality_public = str(reality.get('public-key') or reality.get('public_key') or '')
        reality_short = str(reality.get('short-id') or reality.get('short_id') or '')
    payload = {
        'name': name[:120],
        'protocol': protocol,
        'server': server,
        'port': port,
        'user_id': str(proxy.get('uuid') or proxy.get('id') or ''),
        'password': str(proxy.get('password') or ''),
        'flow': str(proxy.get('flow') or ''),
        'security': security,
        'sni': str(proxy.get('sni') or proxy.get('servername') or ''),
        'fingerprint': str(proxy.get('client-fingerprint') or ('chrome' if security in ('tls', 'reality') else '')),
        'public_key': reality_public,
        'short_id': reality_short,
        'network': network,
        'host': str(ws_headers.get('Host') or ws_headers.get('host') or proxy.get('host') or ''),
        'path': str(ws.get('path') or proxy.get('path') or ''),
        'service_name': str(grpc.get('grpc-service-name') or grpc.get('serviceName') or ''),
        'extra': extra,
        'external_key': 'rule:' + hashlib.sha256(
            json.dumps(proxy, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
        ).hexdigest()[:40],
        'share_link': '',
        'enabled': True,
    }
    return payload


def import_rule_nodes(file_ids: object = None) -> dict:
    state = discover_rule_files()
    if not isinstance(file_ids, list) or not file_ids:
        files = state['files']
    else:
        wanted = {str(item) for item in file_ids}
        files = [item for item in state['files'] if item['id'] in wanted]
    if not files:
        raise ValueError('没有可导入的规则文件')
    nodes = []
    errors = []
    seen = set()
    for file_meta in files:
        path = Path(file_meta['path'])
        try:
            content = path.read_text(encoding='utf-8')
            document = _rule_document(content)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append({'file': file_meta.get('label'), 'error': str(exc)})
            continue
        proxies = document.get('proxies')
        if not isinstance(proxies, list):
            continue
        for index, proxy in enumerate(proxies, start=1):
            try:
                payload = _proxy_to_subscription_node(proxy, file_meta)
                saved = save_subscription_node(payload)
                nodes.append(saved)
                seen.add(saved['id'])
            except (ValueError, TypeError, OSError) as exc:
                errors.append({
                    'file': file_meta.get('label'),
                    'proxy': index,
                    'error': str(exc),
                })
    return {
        'ok': True,
        'imported': len(seen),
        'nodes': nodes,
        'errors': errors,
    }


def _rule_document(content: object) -> dict:
    if not isinstance(content, str):
        raise ValueError('content must be text')
    if len(content.encode('utf-8')) > 4 * 1024 * 1024:
        raise ValueError('content is too large')
    if yaml is None:
        raise ValueError('PyYAML is not installed')
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError('YAML 语法错误: ' + str(exc)) from exc
    if not isinstance(document, dict):
        raise ValueError('YAML 根节点必须是对象')
    rules = document.get('rules')
    if not isinstance(rules, list):
        raise ValueError('YAML 必须包含 rules 数组')
    invalid = [
        index for index, rule in enumerate(rules)
        if not isinstance(rule, str) or not rule.strip()
    ]
    if invalid:
        raise ValueError(
            'rules 第 ' + str(invalid[0] + 1) + ' 项必须是字符串'
        )
    for index, rule in enumerate(rules):
        if (
            rule.split(',', 1)[0].strip().upper() in ('MATCH', 'FINAL') and
            index != len(rules) - 1
        ):
            raise ValueError('MATCH/FINAL 必须是最后一条规则')
    return document


def _rule_groups(document: dict) -> list[str]:
    groups = []
    seen = set()
    for item in document.get('proxy-groups') or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or '').strip()
        if name and name not in seen:
            groups.append(name)
            seen.add(name)
    return groups


def _rule_providers(document: dict) -> list[str]:
    raw = document.get('rule-providers')
    if not isinstance(raw, dict):
        return []
    return sorted(str(name) for name in raw)


def _rule_metadata(path: Path, content: str) -> dict:
    stat = path.stat()
    token = path.parent.name
    metadata = {
        'id': hashlib.sha256(str(path).encode('utf-8')).hexdigest()[:16],
        'label': '订阅规则',
        'path': str(path),
        'token_preview': (
            token[:8] + '…' + token[-6:]
            if len(token) > 16 else token
        ),
        'url': (
            RULE_PUBLIC_BASE + '/' + token + '/mihomo.yaml'
            if RULE_PUBLIC_BASE and re.fullmatch(r'[A-Fa-f0-9]{64}', token)
            else ''
        ),
        'size': stat.st_size,
        'mtime_ms': int(stat.st_mtime * 1000),
        'sha256': hashlib.sha256(content.encode('utf-8')).hexdigest(),
        'mode': '',
        'proxy_count': 0,
        'rule_count': 0,
        'group_count': 0,
        'provider_count': 0,
        'group_names': [],
        'provider_names': [],
        'rule_types': {},
    }
    try:
        document = _rule_document(content)
    except ValueError as exc:
        metadata['yaml_error'] = str(exc)
        return metadata
    proxies = document.get('proxies')
    proxy_count = len(proxies) if isinstance(proxies, list) else 0
    groups = _rule_groups(document)
    providers = _rule_providers(document)
    rules = document['rules']
    rule_types: dict[str, int] = {}
    for rule in rules:
        rule_type = rule.split(',', 1)[0].strip().upper()
        rule_types[rule_type] = rule_types.get(rule_type, 0) + 1
    metadata.update({
        'label': (
            '共享订阅 · 单节点' if proxy_count == 1 else
            '自用订阅 · 多节点' if proxy_count > 1 else '订阅规则'
        ),
        'mode': str(document.get('mode') or ''),
        'proxy_count': proxy_count,
        'rule_count': len(rules),
        'group_count': len(groups),
        'provider_count': len(providers),
        'group_names': groups[:100],
        'provider_names': providers[:100],
        'rule_types': rule_types,
    })
    return metadata


def discover_rule_files() -> dict:
    if not RULE_DIR.is_dir():
        return {
            'ok': True,
            'root': str(RULE_DIR),
            'public_base': RULE_PUBLIC_BASE,
        'target': {'ip': RULE_TARGET_IP, 'name': RULE_TARGET_NAME},
            'files': [],
            'error': '规则目录不存在',
        }
    files = []
    errors = []
    for path in sorted(RULE_DIR.glob('*/mihomo.yaml')):
        try:
            if not path.is_file():
                continue
            stat = path.stat()
            if stat.st_size > 4 * 1024 * 1024:
                errors.append({'path': str(path), 'error': '文件超过 4 MiB'})
                continue
            content = path.read_text(encoding='utf-8')
            files.append(_rule_metadata(path, content))
        except (OSError, UnicodeDecodeError) as exc:
            errors.append({'path': str(path), 'error': str(exc)})
    files.sort(
        key=lambda item: (
            -int(item.get('proxy_count') or 0),
            str(item.get('label') or ''),
            str(item.get('path') or ''),
        )
    )
    result = {
        'ok': True,
        'root': str(RULE_DIR),
        'public_base': RULE_PUBLIC_BASE,
        'target': {'ip': RULE_TARGET_IP, 'name': RULE_TARGET_NAME},
        'files': files,
    }
    if errors:
        result['errors'] = errors
    return result


def _rule_file_metadata(file_id: str) -> dict:
    if not re.fullmatch(r'[A-Fa-f0-9]{16}', file_id):
        raise ValueError('invalid rule file id')
    for item in discover_rule_files()['files']:
        if item['id'] == file_id:
            return item
    raise ValueError('rule file not found')


def read_rule_file(file_id: str) -> dict:
    metadata = _rule_file_metadata(file_id)
    path = Path(metadata['path'])
    try:
        content = path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError('读取规则文件失败: ' + str(exc)) from exc
    result = {
        'ok': True,
        'file': metadata,
        'content': content,
        'rules': [],
        'groups': [],
        'providers': [],
        'proxy_count': 0,
    }
    try:
        document = _rule_document(content)
    except ValueError as exc:
        result['yaml_error'] = str(exc)
        return result
    result.update({
        'mode': str(document.get('mode') or ''),
        'rules': document['rules'],
        'groups': _rule_groups(document),
        'providers': _rule_providers(document),
        'proxy_count': len(document.get('proxies') or []),
    })
    return result


def validate_rule_content(content: object) -> dict:
    document = _rule_document(content)
    rules = document['rules']
    return {
        'ok': True,
        'mode': str(document.get('mode') or ''),
        'rules': rules,
        'groups': _rule_groups(document),
        'providers': _rule_providers(document),
        'proxy_count': len(document.get('proxies') or []),
        'rule_count': len(rules),
    }


def prepare_rule_save(file_id: str, content: object) -> dict:
    metadata = _rule_file_metadata(file_id)
    validated = validate_rule_content(content)
    return {
        **validated,
        'file': metadata,
        'file_id': file_id,
        'path': metadata['path'],
        'sha256': hashlib.sha256(
            str(content).encode('utf-8')
        ).hexdigest(),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ProxyTrafficAggregate/2.2.4'
    sys_version = ''

    def log_message(self, fmt: str, *args: object) -> None:
        message = fmt % args
        message = re.sub(
            r'/sub/[A-Za-z0-9_-]{16,128}',
            '/sub/<redacted>',
            message,
        )
        message = re.sub(
            r'/s/[A-Za-z0-9_-]{4,32}',
            '/s/<redacted>',
            message,
        )
        message = re.sub(
            r'/proxy-traffic-sub/(?:s/)?[A-Za-z0-9_-]{4,128}',
            '/proxy-traffic-sub/<redacted>',
            message,
        )
        log.info('%s - %s', self.client_address[0], message)

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if not getattr(self, '_head_only', False):
            self.wfile.write(body)

    def require_local(self) -> bool:
        try:
            address = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            address = None
        if address is None or not (address.is_private or address.is_loopback):
            self.send_json(403, {'error': 'local access only'})
            return False
        return True

    def send_subscription(
        self,
        body: bytes,
        content_type: str,
        filename: str,
    ) -> None:
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Robots-Tag', 'noindex, nofollow')
        self.end_headers()
        if not getattr(self, '_head_only', False):
            self.wfile.write(body)

    def send_redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Robots-Tag', 'noindex, nofollow')
        self.end_headers()

    def read_json_body(self, maximum: int = 1024 * 1024) -> object:
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('invalid content length') from exc
        if length <= 0 or length > maximum:
            raise ValueError('invalid body size')
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError('invalid json') from exc

    def request_base(self) -> str:
        host = self.headers.get('X-Forwarded-Host') or self.headers.get('Host') or ''
        proto = self.headers.get('X-Forwarded-Proto') or 'http'
        if not host:
            return ''
        return proto.split(',', 1)[0].strip() + '://' + host.split(',', 1)[0].strip() + '/sub'

    def do_HEAD(self) -> None:
        self._head_only = True
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path == '/api/proxy-traffic/sub/state':
                if not self.require_local():
                    return
                self.send_json(200, subscription_state())
                return
            if parsed.path in (
                '/api/proxy-traffic/rules',
                '/api/proxy-traffic/rules/state',
            ):
                if not self.require_local():
                    return
                self.send_json(200, discover_rule_files())
                return
            if parsed.path == '/api/proxy-traffic/rules/file':
                if not self.require_local():
                    return
                file_id = (query.get('file_id') or [''])[0].strip()
                self.send_json(200, read_rule_file(file_id))
                return
            segments = [unquote(segment) for segment in parsed.path.split('/') if segment]
            if segments and segments[0] == 'proxy-traffic-sub':
                segments = ['sub'] + segments[1:]
            if (
                (len(segments) == 2 and segments[0] == 's') or
                (len(segments) == 3 and segments[:2] == ['sub', 's'])
            ):
                code = segments[-1]
                if not SUB_CODE_RE.fullmatch(code):
                    self.send_json(404, {'error': 'subscription not found'})
                    return
                conn = db_connect()
                try:
                    row = conn.execute(
                        'SELECT * FROM subscriptions WHERE short_code = ? AND enabled = 1',
                        (code,),
                    ).fetchone()
                finally:
                    conn.close()
                if row is None:
                    self.send_json(404, {'error': 'subscription not found'})
                    return
                long_url, _ = _subscription_public_urls(row, self.request_base())
                if not long_url:
                    self.send_json(404, {'error': 'subscription base URL is not configured'})
                    return
                requested = (
                    (query.get('format') or query.get('target') or ['auto'])[0]
                )
                normalized = _normalize_subscription_format(requested)
                if normalized != 'auto':
                    long_url += '?format=' + quote(normalized, safe='')
                self.send_redirect(long_url)
                return
            if len(segments) in (2, 3) and segments[0] == 'sub':
                token = segments[1]
                if not SUB_TOKEN_RE.fullmatch(token):
                    self.send_json(404, {'error': 'subscription not found'})
                    return
                conn = db_connect()
                try:
                    row = conn.execute(
                        'SELECT * FROM subscriptions WHERE token = ? AND enabled = 1',
                        (token,),
                    ).fetchone()
                finally:
                    conn.close()
                if row is None:
                    self.send_json(404, {'error': 'subscription not found'})
                    return
                requested = (
                    segments[2] if len(segments) == 3 else
                    (query.get('format') or query.get('target') or ['auto'])[0]
                )
                user_agent = self.headers.get('User-Agent', '')
                body, content_type, filename = render_subscription(
                    row, requested, user_agent,
                )
                self.send_subscription(body, content_type, filename)
                return
            if parsed.path in HEALTH_PATHS:
                self.send_json(200, health())
                return
            if parsed.path in SUMMARY_PATHS:
                self.send_json(200, summary(parse_hours(query)))
                return
            if parsed.path in DEVICE_MAP_PATHS:
                node_id = (query.get('node_id') or [''])[0].strip()
                if not NODE_ID_RE.fullmatch(node_id):
                    raise ValueError('invalid node_id')
                ips = parse_ip_list((query.get('ips') or [''])[0])
                action = (query.get('action') or ['merge'])[0].strip().lower()
                if action == 'reset':
                    removed = reset_device_map(node_id, ips)
                    self.send_json(200, {'ok': True, 'action': 'reset', 'removed': removed})
                    return
                label = (query.get('label') or ['手动设备'])[0]
                device_id = (query.get('device_id') or [''])[0].strip() or None
                device_id = save_device_map(node_id, label, ips, device_id)
                self.send_json(200, {
                    'ok': True,
                    'action': 'merge',
                    'device_id': device_id,
                    'label': label.strip() or '手动设备',
                    'ips': ips,
                })
                return
            if parsed.path in IP_SITES_PATHS:
                hours = parse_hours(query)
                node_id = (query.get('node_id') or [''])[0].strip()
                if not NODE_ID_RE.fullmatch(node_id):
                    raise ValueError('invalid node_id')
                ip = parse_ip((query.get('ip') or [''])[0])
                self.send_json(200, ip_sites(hours, node_id, ip))
                return
            if parsed.path in TIMELINE_PATHS:
                hours = parse_hours(query)
                node_id = (query.get('node_id') or [''])[0].strip()
                if not NODE_ID_RE.fullmatch(node_id):
                    raise ValueError('invalid node_id')
                raw_ips = (query.get('ips') or [''])[0]
                if raw_ips:
                    ips = parse_ip_list(raw_ips)
                else:
                    ips = [parse_ip((query.get('ip') or [''])[0])]
                self.send_json(200, timeline(hours, node_id, ips))
                return
            self.send_json(404, {'error': 'not found'})
        except ValueError as exc:
            self.send_json(400, {'error': str(exc)})
        except sqlite3.Error:
            log.exception('query failed')
            self.send_json(500, {'error': 'database error'})
        except Exception:
            log.exception('query failed')
            self.send_json(500, {'error': 'internal error'})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path in INGEST_PATHS:
            authorization = self.headers.get('Authorization', '')
            supplied = authorization[7:].strip() if authorization.lower().startswith('bearer ') else ''
            if not supplied or not hmac.compare_digest(supplied, INGEST_TOKEN):
                self.send_json(401, {'error': 'unauthorized'})
                return
            try:
                payload = self.read_json_body(MAX_BODY_BYTES)
                accepted = ingest_rows(payload)
            except ValueError as exc:
                self.send_json(400, {'error': str(exc)})
                return
            except sqlite3.Error:
                log.exception('ingest failed')
                self.send_json(500, {'error': 'database error'})
                return
            self.send_json(200, {'ok': True, 'accepted': accepted})
            log.info('ingested %d rows', accepted)
            return
        if parsed.path.startswith('/api/proxy-traffic/rules/'):
            if not self.require_local():
                return
            try:
                payload = self.read_json_body(4 * 1024 * 1024)
                if parsed.path == '/api/proxy-traffic/rules/parse':
                    self.send_json(
                        200,
                        validate_rule_content(
                            payload.get('content') if isinstance(payload, dict) else None
                        ),
                    )
                    return
                if parsed.path == '/api/proxy-traffic/rules/prepare':
                    file_id = _clean_text(
                        payload.get('file_id') if isinstance(payload, dict) else '',
                        'file_id',
                        16,
                        True,
                    )
                    content = (
                        payload.get('content') if isinstance(payload, dict) else None
                    )
                    self.send_json(200, prepare_rule_save(file_id, content))
                    return
                self.send_json(404, {'error': 'not found'})
            except ValueError as exc:
                self.send_json(400, {'error': str(exc)})
            except Exception:
                log.exception('rule operation failed')
                self.send_json(500, {'error': 'internal error'})
            return
        if parsed.path.startswith('/api/proxy-traffic/sub/'):
            if not self.require_local():
                return
            try:
                payload = self.read_json_body()
                if parsed.path == '/api/proxy-traffic/sub/nodes':
                    node = save_subscription_node(payload)
                    self.send_json(200, {'ok': True, 'node': node})
                    return
                if parsed.path == '/api/proxy-traffic/sub/nodes/delete':
                    node_id = _clean_text(
                        payload.get('id') if isinstance(payload, dict) else '',
                        'id',
                        64,
                        True,
                    )
                    removed = delete_subscription_node(node_id)
                    self.send_json(200, {'ok': True, 'removed': removed})
                    return
                if parsed.path == '/api/proxy-traffic/sub/nodes/import':
                    result = import_subscription_links(
                        payload.get('links') if isinstance(payload, dict) else None
                    )
                    self.send_json(200, result)
                    return
                if parsed.path == '/api/proxy-traffic/sub/nodes/import-rules':
                    result = import_rule_nodes(
                        payload.get('file_ids') if isinstance(payload, dict) else None
                    )
                    self.send_json(200, result)
                    return
                if parsed.path == '/api/proxy-traffic/sub/subscriptions':
                    subscription = save_subscription(payload)
                    self.send_json(200, {'ok': True, 'subscription': subscription})
                    return
                if parsed.path == '/api/proxy-traffic/sub/subscriptions/delete':
                    subscription_id = _clean_text(
                        payload.get('id') if isinstance(payload, dict) else '',
                        'id',
                        64,
                        True,
                    )
                    removed = delete_subscription(subscription_id)
                    self.send_json(200, {'ok': True, 'removed': removed})
                    return
                if parsed.path == '/api/proxy-traffic/sub/subscriptions/rotate':
                    subscription_id = _clean_text(
                        payload.get('id') if isinstance(payload, dict) else '',
                        'id',
                        64,
                        True,
                    )
                    subscription = rotate_subscription(subscription_id)
                    self.send_json(200, {'ok': True, 'subscription': subscription})
                    return
                self.send_json(404, {'error': 'not found'})
            except ValueError as exc:
                self.send_json(400, {'error': str(exc)})
            except sqlite3.Error:
                log.exception('subscription operation failed')
                self.send_json(500, {'error': 'database error'})
            return
        self.send_json(404, {'error': 'not found'})


def main() -> None:
    os.umask(0o077)
    init_db()
    open_geo_readers()
    global INGEST_TOKEN
    INGEST_TOKEN = load_token()
    last_prune = 0.0
    conn = db_connect()
    try:
        prune(conn)
    finally:
        conn.close()
    last_prune = time.monotonic()
    server = ThreadingHTTPServer((BIND_ADDRESS, PORT), Handler)
    log.info('listening on %s:%d db=%s', BIND_ADDRESS, PORT, DB_PATH)
    try:
        while True:
            server.handle_request()
            if time.monotonic() - last_prune >= 3600:
                conn = db_connect()
                try:
                    prune(conn)
                finally:
                    conn.close()
                last_prune = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


INGEST_TOKEN = ''

if __name__ == '__main__':
    main()
