#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
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
from urllib.parse import parse_qs, quote, urlsplit

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
NODE_ID_RE = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
SITE_RE = re.compile(r'^[A-Za-z0-9._:-]{1,253}$')
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'ProxyTrafficAggregate/1.0'
    sys_version = ''

    def log_message(self, fmt: str, *args: object) -> None:
        log.info('%s - %s', self.client_address[0], fmt % args)

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        try:
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

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path not in INGEST_PATHS:
            self.send_json(404, {'error': 'not found'})
            return
        authorization = self.headers.get('Authorization', '')
        supplied = authorization[7:].strip() if authorization.lower().startswith('bearer ') else ''
        if not supplied or not hmac.compare_digest(supplied, INGEST_TOKEN):
            self.send_json(401, {'error': 'unauthorized'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            self.send_json(400, {'error': 'invalid content length'})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self.send_json(413, {'error': 'invalid body size'})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
            accepted = ingest_rows(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {'error': 'invalid json'})
            return
        except ValueError as exc:
            self.send_json(400, {'error': str(exc)})
            return
        except sqlite3.Error:
            log.exception('ingest failed')
            self.send_json(500, {'error': 'database error'})
            return
        self.send_json(200, {'ok': True, 'accepted': accepted})
        log.info('ingested %d rows', accepted)


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
