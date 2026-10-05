"""Offline verification: command generation, validation and rollback; no host changes."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import l2tp_bridge as m


def config(role='iran'):
    return dict(role=role, iran_public='192.0.2.1', foreign_public='198.51.100.2',
                iran_tun='10.10.10.1', foreign_tun='10.10.10.2', mtu=1400, forwards=[])


class Tests(unittest.TestCase):
    def test_peer_ids_and_addresses_match(self):
        a, b = m.endpoints(config()), m.endpoints(config('foreign'))
        self.assertEqual(a[0:2], b[1::-1])
        self.assertEqual(a[2:4], b[3:1:-1])
        self.assertEqual(a[4], b[5])
        self.assertEqual(a[6], b[7])
        self.assertIn('name', m.tunnel_commands(config())[1])
        self.assertEqual(m.tunnel_commands(config())[2][3], '10.10.10.1/30')

    def test_invalid_subnet_and_broadcast_rejected(self):
        for ip in ('10.10.11.2', '10.10.10.3', '10.10.10.1'):
            c = config()
            c['foreign_tun'] = ip
            with self.assertRaises(ValueError):
                m.validate(c)

    def test_input_cannot_inject_shell(self):
        for ip in ('1.2.3.4; touch /tmp/no', '::1', '127.0.0.1', '0.0.0.0'):
            with self.assertRaises(ValueError):
                m.ipv4(ip)

    def test_duplicate_ports_and_foreign_forward_rejected(self):
        c = config()
        f = dict(listen=2053, target=443, network='tcp,udp')
        c['forwards'] = [f, copy.deepcopy(f)]
        with self.assertRaises(ValueError):
            m.validate(c)
        c['forwards'] = [f]
        c['role'] = 'foreign'
        with self.assertRaises(ValueError):
            m.validate(c)

    def test_xray_uses_tunnel_ip_and_separate_target_port(self):
        c = config()
        c['forwards'] = [dict(listen=2053, target=443, network='tcp,udp')]
        inbound = m.xray_config(c)['inbounds'][0]
        self.assertEqual(inbound['port'], 2053)
        self.assertEqual(inbound['settings']['rewritePort'], 443)
        self.assertEqual(inbound['settings']['rewriteAddress'], '10.10.10.2')

    def test_partial_tunnel_creation_is_cleaned(self):
        calls = []
        def fake(*args, **kwargs):
            calls.append(args)
            if args[:4] == ('ip', 'l2tp', 'add', 'session'):
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(m, 'load', return_value=config()), patch.object(m, 'collision'), patch.object(m, 'run', side_effect=fake):
            with self.assertRaises(subprocess.CalledProcessError):
                m.tunnel_up()
        self.assertEqual(calls[-1], ('ip', 'l2tp', 'del', 'tunnel', 'tunnel_id', 61001))

    def test_restart_failure_restores_previous_config(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / 'state.json'
            xray = Path(td) / 'xray.json'
            old = config()
            old['forwards'] = [dict(listen=2053, target=443, network='tcp')]
            state.write_text(json.dumps(old))
            xray.write_text('previous relay config')
            new = copy.deepcopy(old)
            new['forwards'].append(dict(listen=2054, target=444, network='udp'))
            failed = False
            def fake(*args, **kwargs):
                nonlocal failed
                if args == ('systemctl', 'restart', m.XRAY_UNIT) and not failed:
                    failed = True
                    raise subprocess.CalledProcessError(1, args)
                return subprocess.CompletedProcess(args, 0, '', '')
            with patch.object(m, 'STATE', state), patch.object(m, 'XRAY_CONFIG', xray), patch.object(m, 'install_xray'), patch.object(m, 'run', side_effect=fake):
                with self.assertRaises(subprocess.CalledProcessError):
                    m.apply_forward(new)
            self.assertEqual(json.loads(state.read_text()), old)
            self.assertEqual(xray.read_text(), 'previous relay config')
            self.assertFalse((Path(td) / 'xray.candidate.json').exists())

    def test_config_validation_failure_leaves_files_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / 'state.json'
            xray = Path(td) / 'xray.json'
            state.write_text(json.dumps(config()))
            xray.write_text('old')
            new = config()
            new['forwards'] = [dict(listen=2053, target=443, network='tcp')]
            def fake(*args, **kwargs):
                if '-test' in args:
                    raise subprocess.CalledProcessError(1, args)
                return subprocess.CompletedProcess(args, 0, '', '')
            with patch.object(m, 'STATE', state), patch.object(m, 'XRAY_CONFIG', xray), patch.object(m, 'install_xray'), patch.object(m, 'run', side_effect=fake):
                with self.assertRaises(subprocess.CalledProcessError):
                    m.apply_forward(new)
            self.assertEqual(json.loads(state.read_text()), config())
            self.assertEqual(xray.read_text(), 'old')


if __name__ == '__main__':
    unittest.main()
