import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

try:
    import yaml
except ImportError:
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
TEMP = tempfile.TemporaryDirectory(prefix='komari-proxy-traffic-test-')
TOKEN_FILE = Path(TEMP.name) / 'ingest-token'
TOKEN_FILE.write_text('x' * 32, encoding='utf-8')
os.environ['PROXY_TRAFFIC_DB'] = str(Path(TEMP.name) / 'aggregate.db')
os.environ['PROXY_TRAFFIC_TOKEN_FILE'] = str(TOKEN_FILE)
sys.path.insert(0, str(ROOT / 'server'))

import server  # noqa: E402


class SubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.init_db()

    def create_node(self, **overrides):
        payload = {
            'name': 'Reality 测试节点',
            'protocol': 'vless',
            'server': '203.0.113.10',
            'port': 443,
            'user_id': '11111111-2222-3333-4444-555555555555',
            'flow': 'xtls-rprx-vision',
            'security': 'reality',
            'sni': 'www.microsoft.com',
            'fingerprint': 'chrome',
            'public_key': 'public-key-test',
            'short_id': 'deadbeef',
            'network': 'tcp',
        }
        payload.update(overrides)
        return server.save_subscription_node(payload)

    def create_subscription(self, node_ids, name='自用'):
        return server.save_subscription({
            'name': name,
            'node_ids': node_ids,
            'base_url': 'https://komari.example.com/proxy-traffic-sub',
            'format': 'auto',
        })

    def get_subscription_row(self, subscription_id):
        conn = server.db_connect()
        try:
            return conn.execute(
                'SELECT * FROM subscriptions WHERE id = ?',
                (subscription_id,),
            ).fetchone()
        finally:
            conn.close()

    def test_render_clash_singbox_and_base64(self):
        node = self.create_node()
        subscription = self.create_subscription([node['id']])
        row = self.get_subscription_row(subscription['id'])

        clash, clash_type, _ = server.render_subscription(row, 'clash', '')
        self.assertEqual(clash_type, 'text/yaml; charset=utf-8')
        clash_text = clash.decode('utf-8')
        clash_payload = (
            yaml.safe_load(clash_text) if yaml is not None
            else json.loads(clash_text)
        )
        proxy = clash_payload['proxies'][0]
        self.assertEqual(proxy['type'], 'vless')
        self.assertEqual(proxy['reality-opts']['public-key'], 'public-key-test')

        singbox, singbox_type, _ = server.render_subscription(row, 'singbox', '')
        self.assertEqual(singbox_type, 'application/json; charset=utf-8')
        singbox_payload = json.loads(singbox.decode('utf-8'))
        outbound = next(item for item in singbox_payload['outbounds'] if item['type'] == 'vless')
        self.assertTrue(outbound['tls']['reality']['enabled'])

        encoded, _, _ = server.render_subscription(row, 'base64', '')
        decoded = base64.b64decode(encoded).decode('utf-8')
        self.assertTrue(decoded.startswith('vless://'))
        self.assertIn('pbk=public-key-test', decoded)

    def test_import_common_protocols(self):
        vmess_payload = base64.b64encode(json.dumps({
            'v': '2',
            'ps': 'VMess 测试',
            'add': 'vmess.example.com',
            'port': '443',
            'id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'net': 'ws',
            'path': '/ws',
            'tls': 'tls',
        }).encode('utf-8')).decode('ascii')
        links = '\n'.join([
            'vless://11111111-2222-3333-4444-555555555555@vless.example.com:443'
            '?encryption=none&security=reality&sni=www.microsoft.com&pbk=key&sid=abcd&type=tcp#VLESS',
            'vmess://' + vmess_payload,
            'trojan://password@trojan.example.com:443?security=tls&sni=trojan.example.com#Trojan',
            'hysteria2://password@hy2.example.com:443?sni=hy2.example.com#HY2',
            'tuic://uuid:password@tuic.example.com:443?sni=tuic.example.com#TUIC',
            'anytls://password@anytls.example.com:443?sni=anytls.example.com#AnyTLS',
        ])
        result = server.import_subscription_links(links)
        self.assertEqual(result['imported'], 6)
        self.assertEqual(result['errors'], [])
        protocols = {item['protocol'] for item in result['nodes']}
        self.assertEqual(
            protocols,
            {'vless', 'vmess', 'trojan', 'hysteria2', 'tuic', 'anytls'},
        )
        for item in result['nodes']:
            self.assertTrue(server._node_uri(item))

    def test_rotate_invalidates_old_token(self):
        node = self.create_node(name='轮换测试节点')
        subscription = self.create_subscription([node['id']], name='轮换测试')
        old_token = subscription['token']
        rotated = server.rotate_subscription(subscription['id'])
        self.assertNotEqual(old_token, rotated['token'])
        conn = server.db_connect()
        try:
            self.assertIsNone(conn.execute(
                'SELECT 1 FROM subscriptions WHERE token = ?',
                (old_token,),
            ).fetchone())
            self.assertIsNotNone(conn.execute(
                'SELECT 1 FROM subscriptions WHERE token = ?',
                (rotated['token'],),
            ).fetchone())
        finally:
            conn.close()

    def test_include_all_uses_enabled_nodes(self):
        first = self.create_node(name='全部节点 A')
        second = self.create_node(name='全部节点 B', port=8443)
        subscription = server.save_subscription({
            'name': '全部节点测试',
            'node_ids': [],
            'include_all': True,
            'base_url': 'https://komari.example.com/proxy-traffic-sub',
        })
        row = self.get_subscription_row(subscription['id'])
        body, _, _ = server.render_subscription(row, 'links', '')
        text = unquote(body.decode('utf-8'))
        self.assertIn(first['name'], text)
        self.assertIn(second['name'], text)


@unittest.skipUnless(yaml is not None, 'PyYAML is required for rule tests')
class RuleFileTests(unittest.TestCase):
    def setUp(self):
        self.old_rule_dir = server.RULE_DIR
        self.old_public_base = server.RULE_PUBLIC_BASE
        self.rule_dir = Path(TEMP.name) / 'premium'
        token = 'a' * 64
        directory = self.rule_dir / token
        directory.mkdir(parents=True, exist_ok=True)
        self.rule_path = directory / 'mihomo.yaml'
        document = {
            'mode': 'global',
            'proxies': [{'name': 'A'}, {'name': 'B'}],
            'proxy-groups': [{'name': '🚀 节点选择', 'type': 'select'}],
            'rule-providers': {'acl_ai': {'type': 'http'}},
            'rules': [
                'DOMAIN-SUFFIX,example.com,🚀 节点选择',
                'MATCH,DIRECT',
            ],
        }
        self.rule_path.write_text(
            yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
            encoding='utf-8',
        )
        server.RULE_DIR = self.rule_dir
        server.RULE_PUBLIC_BASE = 'https://premium.example.com'

    def tearDown(self):
        server.RULE_DIR = self.old_rule_dir
        server.RULE_PUBLIC_BASE = self.old_public_base

    def test_discover_read_and_prepare(self):
        state = server.discover_rule_files()
        self.assertEqual(len(state['files']), 1)
        item = state['files'][0]
        self.assertIn('自用订阅', item['label'])
        self.assertEqual(item['proxy_count'], 2)
        self.assertEqual(item['rule_count'], 2)
        self.assertEqual(item['group_count'], 1)
        self.assertTrue(item['url'].endswith('/mihomo.yaml'))
        data = server.read_rule_file(item['id'])
        self.assertEqual(data['rules'][0], 'DOMAIN-SUFFIX,example.com,🚀 节点选择')
        self.assertEqual(data['groups'], ['🚀 节点选择'])
        self.assertEqual(data['providers'], ['acl_ai'])
        prepared = server.prepare_rule_save(
            item['id'],
            self.rule_path.read_text(encoding='utf-8'),
        )
        self.assertEqual(prepared['path'], str(self.rule_path))
        self.assertEqual(prepared['rule_count'], 2)

    def test_validate_rejects_bad_yaml(self):
        with self.assertRaises(ValueError):
            server.validate_rule_content('rules: [')
        with self.assertRaises(ValueError):
            server.validate_rule_content('mode: global\nrules: not-a-list\n')


if __name__ == '__main__':
    unittest.main()
