#!/usr/bin/env python3
"""Standalone L2TPv3/IP tunnel and dedicated Xray port-forward manager."""
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

BASE = Path('/opt/l2tpbridge')
STATE = Path('/etc/l2tpbridge/state.json')
XRAY_CONFIG = STATE.parent / 'xray.json'
TUN_UNIT = 'l2tpbridge-tunnel.service'
XRAY_UNIT = 'l2tpbridge-xray.service'
IFACE = 'lb-l2tp0'


def run(*args, check=True, capture=False):
    return subprocess.run([str(a) for a in args], check=check, text=True,
                          capture_output=capture, timeout=120)


def write(path, data, mode=0o600):
    """Atomically replace a managed file, never evaluate user input as shell."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(c):
    write(STATE, json.dumps(c, indent=2) + '\n')


def load():
    if not STATE.exists():
        raise ValueError('Run Setup Iran or Setup Foreign first.')
    c = json.loads(STATE.read_text())
    validate(c)
    return c


def ipv4(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or int(ip) == 0xffffffff:
        raise ValueError('Enter a unicast IPv4 address.')
    return str(ip)


def port(value):
    p = int(value)
    if not 1 <= p <= 65535:
        raise ValueError('Port must be 1..65535.')
    return p


def validate(c):
    if c['role'] not in ('iran', 'foreign'):
        raise ValueError('Invalid role')
    for k in ('iran_public', 'foreign_public', 'iran_tun', 'foreign_tun'):
        ipv4(c[k])
    if c['iran_public'] == c['foreign_public']:
        raise ValueError('Server public IPs must differ.')
    net = ipaddress.IPv4Network(c['iran_tun'] + '/30', strict=False)
    if c['iran_tun'] == c['foreign_tun'] or ipaddress.IPv4Address(c['foreign_tun']) not in net:
        raise ValueError('Tunnel IPs must differ and belong to the same /30.')
    if any(ipaddress.IPv4Address(c[k]) not in list(net.hosts()) for k in ('iran_tun', 'foreign_tun')):
        raise ValueError('Use the two host IPs in the /30, not network/broadcast.')
    if not net.is_private:
        raise ValueError('Use a private /30 subnet for the tunnel.')
    if not 576 <= int(c['mtu']) <= 1400:
        raise ValueError('MTU must be 576..1400.')
    seen = set()
    for f in c['forwards']:
        p = port(f['listen'])
        port(f['target'])
        if f['network'] not in ('tcp', 'udp', 'tcp,udp') or p in seen:
            raise ValueError('Duplicate listening port or invalid network.')
        seen.add(p)
    if c['role'] == 'foreign' and c['forwards']:
        raise ValueError('Forwards belong on Iran only.')


def endpoints(c):
    iran = c['role'] == 'iran'
    return (c['iran_public'] if iran else c['foreign_public'],
            c['foreign_public'] if iran else c['iran_public'],
            c['iran_tun'] if iran else c['foreign_tun'],
            c['foreign_tun'] if iran else c['iran_tun'],
            61001 if iran else 61002, 61002 if iran else 61001,
            62001 if iran else 62002, 62002 if iran else 62001)


def tunnel_commands(c):
    local, remote, own, peer, tid, ptid, sid, psid = endpoints(c)
    return [
        ['ip', 'l2tp', 'add', 'tunnel', 'tunnel_id', str(tid), 'peer_tunnel_id', str(ptid),
         'encap', 'ip', 'local', local, 'remote', remote],
        ['ip', 'l2tp', 'add', 'session', 'tunnel_id', str(tid), 'session_id', str(sid),
         'peer_session_id', str(psid), 'name', IFACE],
        ['ip', 'addr', 'add', own + '/30', 'dev', IFACE],
        ['ip', 'link', 'set', 'dev', IFACE, 'mtu', str(c['mtu']), 'up']]


def collision(c):
    """Never take over an existing unmanaged tunnel ID or interface."""
    tid = endpoints(c)[4]
    if run('ip', 'link', 'show', 'dev', IFACE, check=False, capture=True).returncode == 0:
        raise ValueError(f'Interface {IFACE} already exists; refusing to take it over.')
    text = run('ip', 'l2tp', 'show', 'tunnel', capture=True).stdout
    if re.search(rf'^Tunnel\s+{tid},', text, re.M):
        raise ValueError(f'Tunnel ID {tid} is already in use.')


def tunnel_up():
    c = load()
    for module in ('l2tp_core', 'l2tp_ip', 'l2tp_eth'):
        run('modprobe', module)
    collision(c)
    created = False
    try:
        for i, cmd in enumerate(tunnel_commands(c)):
            run(*cmd)
            if i == 0:
                created = True
    except Exception:
        if created:
            run('ip', 'l2tp', 'del', 'tunnel', 'tunnel_id', endpoints(c)[4], check=False)
        raise


def tunnel_down():
    """Called only by the unit that successfully created our tunnel."""
    c = load()
    if run('ip', 'link', 'show', 'dev', IFACE, check=False, capture=True).returncode == 0:
        run('ip', 'l2tp', 'del', 'tunnel', 'tunnel_id', endpoints(c)[4])


def xray_config(c):
    # Current Xray name for dokodemo-door: tunnel, with rewrite settings.
    return {'log': {'loglevel': 'warning'}, 'inbounds': [
        {'tag': f"forward-{f['listen']}", 'listen': '0.0.0.0', 'port': f['listen'],
         'protocol': 'tunnel', 'settings': {
             'rewriteAddress': c['foreign_tun'], 'rewritePort': f['target'],
             'allowedNetwork': f['network'], 'followRedirect': False}}
        for f in c['forwards']],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}]}


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'l2tpbridge/1.0',
                                               'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def install_xray():
    """Install a private binary, verified by the official release SHA256 digest."""
    binary = BASE / 'xray'
    if binary.exists():
        return
    arch = {'x86_64': '64', 'aarch64': 'arm64-v8a'}.get(platform.machine())
    if not arch:
        raise ValueError('Supported architectures: x86_64 and aarch64.')
    print('Downloading official Xray release (GitHub access required)...')
    release = json.loads(get('https://api.github.com/repos/XTLS/Xray-core/releases/latest'))
    name = f'Xray-linux-{arch}.zip'
    asset = next((a for a in release['assets'] if a['name'] == name), None)
    if not asset:
        raise ValueError(f'Official release has no {name}')
    digest = asset.get('digest') or ''
    if not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', digest):
        raise ValueError('Official SHA256 digest missing; download refused.')
    data = get(asset['browser_download_url'])
    if hashlib.sha256(data).hexdigest().lower() != digest[7:].lower():
        raise ValueError('Xray archive SHA256 mismatch.')
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        blob = z.read('xray')
    candidate = BASE / 'xray.new'
    candidate.write_bytes(blob)
    candidate.chmod(0o755)
    try:
        run(candidate, 'version')
        os.replace(candidate, binary)
    finally:
        candidate.unlink(missing_ok=True)
    write(BASE / 'xray-version.txt', release['tag_name'] + '\n', 0o644)


def units():
    write(Path('/etc/systemd/system') / TUN_UNIT, f'''[Unit]
Description=L2TPBridge managed L2TPv3/IP tunnel
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {BASE}/l2tp_bridge.py tunnel-up
ExecStop=/usr/bin/python3 {BASE}/l2tp_bridge.py tunnel-down
TimeoutStartSec=60
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
''', 0o644)
    write(Path('/etc/systemd/system') / XRAY_UNIT, f'''[Unit]
Description=L2TPBridge dedicated Xray port relay
Requires={TUN_UNIT}
After={TUN_UNIT}
PartOf={TUN_UNIT}

[Service]
ExecStart={BASE}/xray run -config {XRAY_CONFIG}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
''', 0o644)
    run('systemctl', 'daemon-reload')


def apply_forward(c):
    """Validate the candidate first, then roll back files and relay on failure."""
    validate(c)
    if c['role'] != 'iran':
        raise ValueError('Configure forwarding on Iran only.')
    if c['forwards']:
        install_xray()
    old_state = STATE.read_text()
    old_xray = XRAY_CONFIG.read_text() if XRAY_CONFIG.exists() else None
    candidate = STATE.parent / 'xray.candidate.json'
    write(candidate, json.dumps(xray_config(c), indent=2))
    try:
        if c['forwards']:
            try:
                run(BASE / 'xray', 'run', '-test', '-config', candidate)
            except subprocess.CalledProcessError:
                compat = xray_config(c)
                for inbound in compat['inbounds']:
                    settings = inbound['settings']
                    inbound['protocol'] = 'dokodemo-door'
                    inbound['settings'] = {
                        'address': settings['rewriteAddress'], 'port': settings['rewritePort'],
                        'network': settings['allowedNetwork'], 'followRedirect': False}
                write(candidate, json.dumps(compat, indent=2))
                run(BASE / 'xray', 'run', '-test', '-config', candidate)
        write(XRAY_CONFIG, candidate.read_text())
        save(c)
        if c['forwards']:
            run('systemctl', 'enable', XRAY_UNIT)
            run('systemctl', 'restart', XRAY_UNIT)
            time.sleep(1)
            run('systemctl', 'is-active', '--quiet', XRAY_UNIT)
        else:
            run('systemctl', 'disable', '--now', XRAY_UNIT)
    except Exception:
        write(STATE, old_state)
        if old_xray is not None:
            write(XRAY_CONFIG, old_xray)
        else:
            XRAY_CONFIG.unlink(missing_ok=True)
        old = json.loads(old_state)
        if old['forwards']:
            run('systemctl', 'enable', XRAY_UNIT, check=False)
            run('systemctl', 'restart', XRAY_UNIT, check=False)
        else:
            run('systemctl', 'disable', '--now', XRAY_UNIT, check=False)
        raise
    finally:
        candidate.unlink(missing_ok=True)


def ask(label, default=None, parser=str):
    while True:
        s = input(label + (f' [{default}]' if default is not None else '') + ': ').strip()
        try:
            if not s:
                if default is None:
                    raise ValueError('A value is required.')
                s = str(default)
            return parser(s)
        except (ValueError, TypeError) as e:
            print('Invalid:', e)


def setup(role):
    if STATE.exists():
        raise ValueError('Already configured. Use Uninstall before changing tunnel endpoints.')
    c = {'role': role, 'iran_public': ask('Iran server IPv4', parser=ipv4),
         'foreign_public': ask('Foreign server IPv4', parser=ipv4),
         'iran_tun': ask('Iran tunnel IPv4', '10.10.10.1', ipv4),
         'foreign_tun': ask('Foreign tunnel IPv4', '10.10.10.2', ipv4),
         'mtu': ask('Tunnel MTU', 1400, int), 'forwards': []}
    validate(c)
    local = endpoints(c)[0]
    addresses = json.loads(run('ip', '-j', '-4', 'addr', 'show', capture=True).stdout)
    if not any(a.get('local') == local for dev in addresses for a in dev.get('addr_info', [])):
        raise ValueError(f'{local} is not assigned locally. This installer requires direct IPv4, without NAT.')
    # Catch overlapping routes; do not silently steal a subnet from other services.
    net = ipaddress.IPv4Network(c['iran_tun'] + '/30', strict=False)
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all', capture=True).stdout)
    for r in routes:
        dest = r.get('dst', 'default')
        if dest != 'default' and net.overlaps(ipaddress.IPv4Network(dest, strict=False)):
            raise ValueError(f'Tunnel subnet overlaps existing route {dest}; select another /30 on both hosts.')
    for module in ('l2tp_core', 'l2tp_ip', 'l2tp_eth'):
        run('modprobe', module)
    collision(c)
    print(json.dumps(c, indent=2))
    if ask('Create this tunnel? yes/no', 'yes').lower() != 'yes':
        return
    save(c)
    units()
    try:
        run('systemctl', 'enable', '--now', TUN_UNIT)
    except Exception:
        run('systemctl', 'disable', '--now', TUN_UNIT, check=False)
        STATE.unlink(missing_ok=True)
        raise
    print('Tunnel created and enabled at boot. Set up the other server with identical IPs.')
    print('Allow IP protocol 115 from the peer in host/provider firewalls. This is NOT TCP/UDP port 115.')
    if role == 'iran' and ask('Add a forwarding port now? yes/no', 'yes').lower() == 'yes':
        add_forward()


def add_forward():
    c = load()
    if c['role'] != 'iran':
        raise ValueError('Add forwarding on Iran only.')
    f = {'listen': ask('Listening port on Iran', 2053, port),
         'target': ask('Destination service port on Foreign', 2053, port),
         'network': ask('Protocol: tcp / udp / tcp,udp', 'tcp,udp')}
    new = copy.deepcopy(c)
    new['forwards'].append(f)
    validate(new)
    # Query sockets without stopping any existing service.
    for proto in f['network'].split(','):
        result = run('ss', '-H', '-lnt' if proto == 'tcp' else '-lnu',
                     'sport', '=', f":{f['listen']}", capture=True)
        if result.stdout.strip():
            raise ValueError(f"Port {f['listen']}/{proto} already has a listener.")
    apply_forward(new)
    print(f"Forward enabled: Iran:{f['listen']} -> {c['foreign_tun']}:{f['target']} ({f['network']})")
    print('Allow this listening port in Iran host/provider firewalls.')
    print('Foreign service must listen on the tunnel IP or 0.0.0.0, with firewall access from Iran tunnel IP.')


def remove_forward():
    c = load()
    print(json.dumps(c['forwards'], indent=2))
    p = ask('Listening port to remove', parser=port)
    new = copy.deepcopy(c)
    new['forwards'] = [f for f in c['forwards'] if f['listen'] != p]
    if new == c:
        raise ValueError('That forwarding port does not exist.')
    apply_forward(new)
    print('Port removed.')


def status():
    c = load()
    print(json.dumps(c, indent=2))
    for unit in (TUN_UNIT, XRAY_UNIT):
        run('systemctl', '--no-pager', '--full', 'status', unit, check=False)
    run('ip', '-s', 'link', 'show', 'dev', IFACE, check=False)
    run('ss', '-lntup', check=False)


def test():
    c = load()
    peer = endpoints(c)[3]
    print('Tunnel ping (failure can also mean ICMP is filtered):')
    run('ping', '-I', IFACE, '-c', '3', '-W', '2', peer, check=False)
    if c['role'] == 'iran':
        for f in c['forwards']:
            if 'tcp' in f['network']:
                for host, p, label in [(peer, f['target'], 'Foreign TCP service'),
                                        ('127.0.0.1', f['listen'], 'Local relay listener')]:
                    try:
                        with socket.create_connection((host, p), timeout=4):
                            print(f'OK {label}: {host}:{p}')
                    except OSError as e:
                        print(f'FAIL {label}: {e}')
            if 'udp' in f['network']:
                print(f"UDP {f['listen']}: requires an actual application request/reply; not inferred from ping.")
    print('A TCP connect to the local relay proves its listener only. Test your real client to confirm forwarding.')


def uninstall():
    if ask('Remove this installer and its own tunnel/forwards? Type REMOVE', '') != 'REMOVE':
        return
    for unit in (XRAY_UNIT, TUN_UNIT):
        run('systemctl', 'disable', '--now', unit, check=False)
    # Preserve config if kernel cleanup failed, so ownership is not lost.
    if run('ip', 'link', 'show', 'dev', IFACE, check=False, capture=True).returncode == 0:
        raise ValueError('Managed interface still exists. Cleanup failed; configuration preserved. Check logs.')
    for unit in (XRAY_UNIT, TUN_UNIT):
        (Path('/etc/systemd/system') / unit).unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    shutil.rmtree(STATE.parent, ignore_errors=True)
    shutil.rmtree(BASE, ignore_errors=True)
    Path('/usr/local/bin/l2tpbridge').unlink(missing_ok=True)
    print('Uninstalled. Existing firewall rules were not changed.')


def menu():
    actions = {'1': lambda: setup('foreign'), '2': lambda: setup('iran'),
               '3': add_forward, '4': remove_forward, '5': status, '6': test,
               '7': lambda: run('journalctl', '-u', TUN_UNIT, '-u', XRAY_UNIT, '-n', '80', '--no-pager'),
               '8': lambda: run('systemctl', 'restart', TUN_UNIT), '9': uninstall}
    while True:
        print('\n\033[1;36mL2TPBridge | v1.0\033[0m\n'
              '1) Setup Foreign server\n2) Setup Iran server\n3) Add forwarding port\n'
              '4) Remove forwarding port\n5) Status\n6) Connection tests\n7) Logs\n'
              '8) Restart tunnel + relay\n9) Uninstall\n0) Exit')
        choice = input('Select: ').strip()
        if choice == '0':
            return
        try:
            if choice not in actions:
                print('Choose 0..9.')
                continue
            actions[choice]()
            if choice == '9' and not BASE.exists():
                return
        except Exception as e:
            print(f'ERROR: {e}\nUse option 7 for service logs; configuration may still need attention.')


def main():
    if os.geteuid() != 0:
        raise ValueError('Run with sudo/root.')
    action = sys.argv[1] if len(sys.argv) > 1 else 'menu'
    if action == 'tunnel-up':
        tunnel_up()
    elif action == 'tunnel-down':
        tunnel_down()
    else:
        # Unit callbacks deliberately do not take this lock: systemctl waits for them.
        with open('/run/l2tpbridge.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            {'menu': menu, 'status': status, 'test': test, 'add': add_forward,
             'remove': remove_forward}.get(action, lambda: (_ for _ in ()).throw(ValueError('Unknown command')))()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.')
        sys.exit(130)
    except Exception as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
