#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG_PATH = Path('/etc/proxy-traffic/config.json')
DEFAULT_DB = Path('/var/lib/proxy-traffic/traffic.db')
POLL_SECONDS = 1.0
UPLOAD_SECONDS = 30.0
DEFAULT_PROTOCOLS = ('*',)
FLOW_RETENTION_SECONDS = 24 * 60 * 60
MINUTE_RETENTION_SECONDS = 30 * 24 * 60 * 60
MINUTE_DETAIL_SECONDS = 2 * 24 * 60 * 60
ACTIVE_RETENTION_SECONDS = 10 * 60
MAX_BATCH_ROWS = 2000
SITE_RE = re.compile(r'^[a-z0-9._:-]{1,253}$')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z',
)
log = logging.getLogger('traffic-collector')
stop_event = threading.Event()


def load_config() -> dict:
    config = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    required = ('clash_api', 'clash_secret_file', 'ingest_url', 'node_id', 'node_name')
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise RuntimeError(f'missing config keys: {", ".join(missing)}')
    if not config.get('ingest_token') and not config.get('ingest_token_file'):
        raise RuntimeError('missing config keys: ingest_token or ingest_token_file')
    if not config.get('ingest_token'):
        config['ingest_token'] = Path(config['ingest_token_file']).read_text(
            encoding='utf-8'
        ).strip()
    if not config['ingest_token']:
        raise RuntimeError('ingest token is empty')
    protocols = config.get('protocols', list(DEFAULT_PROTOCOLS))
    if protocols is None:
        protocols = list(DEFAULT_PROTOCOLS)
    if not isinstance(protocols, list) or not protocols:
        raise RuntimeError('protocols must be a non-empty array or ["*"]')
    normalized_protocols = []
    for value in protocols:
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError('protocols entries must be non-empty strings')
        normalized_protocols.append(value.strip().lower())
    config['protocols'] = normalized_protocols
    return config


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    path.chmod(0o600)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA busy_timeout=15000')
    conn.executescript(
        '''
        CREATE TABLE IF NOT EXISTS active_conn (
            id TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            up_seen INTEGER NOT NULL,
            down_seen INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            up_bytes INTEGER NOT NULL,
            down_bytes INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen);
        CREATE TABLE IF NOT EXISTS minute_stats (
            minute INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            up_bytes INTEGER NOT NULL,
            down_bytes INTEGER NOT NULL,
            connections INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            PRIMARY KEY (minute, source_ip)
        );
        CREATE INDEX IF NOT EXISTS idx_minute_stats_minute ON minute_stats(minute);
        CREATE TABLE IF NOT EXISTS minute_conn (
            minute INTEGER NOT NULL,
            conn_id TEXT NOT NULL,
            PRIMARY KEY (minute, conn_id)
        );
        CREATE INDEX IF NOT EXISTS idx_minute_conn_minute ON minute_conn(minute);
        CREATE TABLE IF NOT EXISTS site_stats (
            minute INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            site TEXT NOT NULL,
            up_bytes INTEGER NOT NULL,
            down_bytes INTEGER NOT NULL,
            connections INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            PRIMARY KEY (minute, source_ip, site)
        );
        CREATE INDEX IF NOT EXISTS idx_site_stats_minute ON site_stats(minute);
        CREATE TABLE IF NOT EXISTS minute_site_conn (
            minute INTEGER NOT NULL,
            conn_id TEXT NOT NULL,
            site TEXT NOT NULL,
            PRIMARY KEY (minute, conn_id, site)
        );
        CREATE INDEX IF NOT EXISTS idx_minute_site_conn_minute ON minute_site_conn(minute);
        '''
    )
    conn.commit()
    return conn


def parse_start(value: str | None, fallback_ms: int) -> int:
    if not value:
        return fallback_ms
    normalized = re.sub(r'(\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
    try:
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return int(parsed.timestamp() * 1000)
    except (ValueError, TypeError):
        return fallback_ms


def valid_source(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global:
        return None
    return address.compressed


def normalize_site(value: object, destination_ip: object = None) -> str | None:
    site = str(value or '').strip().lower().rstrip('.')
    if not site and destination_ip:
        try:
            address = ipaddress.ip_address(str(destination_ip).strip())
            if address.is_global:
                site = 'ip:' + address.compressed
        except ValueError:
            site = ''
    if not site:
        return None
    if site.startswith('[') and ']' in site:
        site = site[1:site.index(']')]
    elif site.count(':') == 1 and re.search(r':\d+$', site):
        site = site.rsplit(':', 1)[0]
    if not SITE_RE.fullmatch(site):
        return None
    return site


def fetch_connections(api_url: str, secret: str) -> list[dict]:
    request = urllib.request.Request(
        api_url.rstrip('/') + '/connections',
        headers={
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + secret,
            'User-Agent': 'komari-proxy-traffic/1',
        },
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = json.load(response)
    connections = payload.get('connections')
    return connections if isinstance(connections, list) else []


def record_poll(
    conn: sqlite3.Connection,
    connections: list[dict],
    now_ms: int,
    protocols: list[str],
) -> None:
    minute = (now_ms // 60000) * 60000
    seen: set[str] = set()
    rows = conn.execute(
        'SELECT id, up_seen, down_seen FROM active_conn'
    ).fetchall()
    previous = {row['id']: (int(row['up_seen']), int(row['down_seen'])) for row in rows}

    with conn:
        for item in connections:
            if not isinstance(item, dict):
                continue
            conn_id = str(item.get('id') or '').strip()
            metadata = item.get('metadata') or {}
            source_ip = valid_source(metadata.get('sourceIP'))
            conn_type = str(metadata.get('type') or item.get('type') or '')
            if not conn_id or not source_ip:
                continue
            if '*' not in protocols and not any(
                conn_type.startswith(protocol) for protocol in protocols
            ):
                continue
            site = normalize_site(metadata.get('host'), metadata.get('destinationIP'))
            seen.add(conn_id)
            up_now = max(0, int(item.get('upload') or 0))
            down_now = max(0, int(item.get('download') or 0))
            old = previous.get(conn_id)
            if old is None:
                # The first observation only establishes a baseline. The Clash
                # counters are cumulative for the connection, so counting this
                # value would attribute traffic from before collector start.
                delta_up = 0
                delta_down = 0
            else:
                old_up, old_down = old
                delta_up = up_now - old_up if up_now >= old_up else up_now
                delta_down = down_now - old_down if down_now >= old_down else down_now
            start_ms = parse_start(item.get('start'), now_ms)

            conn.execute(
                '''
                INSERT INTO flows(id, source_ip, first_seen, last_seen, up_bytes, down_bytes)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source_ip=excluded.source_ip,
                    last_seen=excluded.last_seen,
                    up_bytes=flows.up_bytes + excluded.up_bytes,
                    down_bytes=flows.down_bytes + excluded.down_bytes
                ''',
                (conn_id, source_ip, start_ms, now_ms, delta_up, delta_down),
            )
            conn.execute(
                '''
                INSERT INTO active_conn(id, source_ip, up_seen, down_seen, first_seen, last_seen)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source_ip=excluded.source_ip,
                    up_seen=excluded.up_seen,
                    down_seen=excluded.down_seen,
                    last_seen=excluded.last_seen
                ''',
                (conn_id, source_ip, up_now, down_now, start_ms, now_ms),
            )
            changes_before = conn.total_changes
            conn.execute(
                'INSERT OR IGNORE INTO minute_conn(minute, conn_id) VALUES(?, ?)',
                (minute, conn_id),
            )
            connection_increment = 1 if conn.total_changes > changes_before else 0
            conn.execute(
                '''
                INSERT INTO minute_stats(minute, source_ip, up_bytes, down_bytes, connections, last_seen)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(minute, source_ip) DO UPDATE SET
                    up_bytes=minute_stats.up_bytes + excluded.up_bytes,
                    down_bytes=minute_stats.down_bytes + excluded.down_bytes,
                    connections=minute_stats.connections + excluded.connections,
                    last_seen=excluded.last_seen
                ''',
                (minute, source_ip, delta_up, delta_down, connection_increment, now_ms),
            )
            if site:
                changes_before = conn.total_changes
                conn.execute(
                    'INSERT OR IGNORE INTO minute_site_conn(minute, conn_id, site) VALUES(?, ?, ?)',
                    (minute, conn_id, site),
                )
                site_connection_increment = 1 if conn.total_changes > changes_before else 0
                conn.execute(
                    '''
                    INSERT INTO site_stats(
                        minute, source_ip, site, up_bytes, down_bytes, connections, last_seen
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(minute, source_ip, site) DO UPDATE SET
                        up_bytes=site_stats.up_bytes + excluded.up_bytes,
                        down_bytes=site_stats.down_bytes + excluded.down_bytes,
                        connections=site_stats.connections + excluded.connections,
                        last_seen=excluded.last_seen
                    ''',
                    (
                        minute, source_ip, site, delta_up, delta_down,
                        site_connection_increment, now_ms,
                    ),
                )

        conn.execute(
            'DELETE FROM active_conn WHERE last_seen < ?',
            (now_ms - ACTIVE_RETENTION_SECONDS * 1000,),
        )


def prune(conn: sqlite3.Connection, now_ms: int) -> None:
    now = now_ms // 1000
    with conn:
        conn.execute('DELETE FROM flows WHERE last_seen < ?', ((now - FLOW_RETENTION_SECONDS) * 1000,))
        conn.execute('DELETE FROM minute_stats WHERE minute < ?', ((now - MINUTE_RETENTION_SECONDS) * 1000,))
        conn.execute('DELETE FROM minute_conn WHERE minute < ?', ((now - MINUTE_DETAIL_SECONDS) * 1000,))
        conn.execute('DELETE FROM site_stats WHERE minute < ?', ((now - MINUTE_RETENTION_SECONDS) * 1000,))
        conn.execute('DELETE FROM minute_site_conn WHERE minute < ?', ((now - MINUTE_DETAIL_SECONDS) * 1000,))
        conn.execute(
            'DELETE FROM active_conn WHERE last_seen < ?',
            ((now - ACTIVE_RETENTION_SECONDS) * 1000,),
        )


def post_batch(config: dict, rows: list[list[int | str]], site_rows: list[list[int | str]]) -> None:
    if not rows and not site_rows:
        return
    body = json.dumps(
        {
            'node_id': config['node_id'],
            'node_name': config['node_name'],
            'generated_at': int(time.time() * 1000),
            'rows': rows,
            'site_rows': site_rows,
        },
        ensure_ascii=False,
        separators=(',', ':'),
    ).encode('utf-8')
    request = urllib.request.Request(
        config['ingest_url'],
        data=body,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + config['ingest_token'],
            'User-Agent': 'komari-proxy-traffic/1',
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f'ingest returned {response.status}')
        response.read(256)


def upload_loop(config: dict, db_path: Path) -> None:
    conn = open_db(db_path)
    first_upload = True
    next_prune = time.monotonic() + 300
    while not stop_event.is_set():
        now_ms = int(time.time() * 1000)
        since = now_ms - (3 * 60 * 60 * 1000 if first_upload else 15 * 60 * 1000)
        try:
            rows = conn.execute(
                '''
                SELECT minute, source_ip, up_bytes, down_bytes, connections, last_seen
                FROM minute_stats
                WHERE minute >= ?
                ORDER BY minute, source_ip
                ''',
                (since,),
            ).fetchall()
            site_rows = conn.execute(
                '''
                SELECT minute, source_ip, site, up_bytes, down_bytes, connections, last_seen
                FROM site_stats
                WHERE minute >= ?
                ORDER BY minute, site, source_ip
                ''',
                (since,),
            ).fetchall()
            for offset in range(0, max(len(rows), len(site_rows)), MAX_BATCH_ROWS):
                chunk = rows[offset:offset + MAX_BATCH_ROWS]
                site_chunk = site_rows[offset:offset + MAX_BATCH_ROWS]
                payload = [
                    [int(row['minute']), row['source_ip'], int(row['up_bytes']),
                     int(row['down_bytes']), int(row['connections']), int(row['last_seen'])]
                    for row in chunk
                ]
                site_payload = [
                    [int(row['minute']), row['source_ip'], row['site'],
                     int(row['up_bytes']), int(row['down_bytes']),
                     int(row['connections']), int(row['last_seen'])]
                    for row in site_chunk
                ]
                post_batch(config, payload, site_payload)
            if rows or site_rows:
                log.info(
                    'uploaded %d aggregate rows, %d site rows',
                    len(rows), len(site_rows),
                )
            first_upload = False
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            log.warning('upload failed: %s', exc)

        if time.monotonic() >= next_prune:
            try:
                prune(conn, int(time.time() * 1000))
            except sqlite3.Error as exc:
                log.warning('prune failed: %s', exc)
            next_prune = time.monotonic() + 300

        stop_event.wait(UPLOAD_SECONDS)
    conn.close()


def poll_loop(config: dict, db_path: Path) -> None:
    secret = Path(config['clash_secret_file']).read_text(encoding='utf-8').strip()
    conn = open_db(db_path)
    next_prune = time.monotonic() + 300
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            connections = fetch_connections(config['clash_api'], secret)
            record_poll(conn, connections, int(time.time() * 1000), config['protocols'])
            if consecutive_errors:
                log.info('Clash API recovered')
            consecutive_errors = 0
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, sqlite3.Error) as exc:
            consecutive_errors += 1
            if consecutive_errors == 1 or consecutive_errors % 30 == 0:
                log.warning('poll failed (%d): %s', consecutive_errors, exc)

        if time.monotonic() >= next_prune:
            try:
                prune(conn, int(time.time() * 1000))
            except sqlite3.Error as exc:
                log.warning('prune failed: %s', exc)
            next_prune = time.monotonic() + 300
        stop_event.wait(POLL_SECONDS)
    conn.close()


def handle_signal(_signum, _frame) -> None:
    stop_event.set()


def main() -> None:
    os.umask(0o077)
    config = load_config()
    db_path = Path(config.get('db_path') or DEFAULT_DB)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    log.info('collector starting node=%s db=%s', config['node_id'], db_path)
    uploader = threading.Thread(target=upload_loop, args=(config, db_path), name='uploader', daemon=True)
    uploader.start()
    try:
        poll_loop(config, db_path)
    finally:
        stop_event.set()
        uploader.join(timeout=5)
        log.info('collector stopped')


if __name__ == '__main__':
    main()
