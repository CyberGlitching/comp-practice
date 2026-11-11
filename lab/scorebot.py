#!/usr/bin/env python3
"""
scorebot.py - a stand-in for the competition scoring engine (the packet calls it DSSS).
Checks each scored service on a cadence (default 30s, like the real one) and serves a live
web scoreboard so you SEE a service go red the instant your hardening breaks it. Pure stdlib.

  python3 scorebot.py --config services.yml [--interval 30] [--port 8080]
  then open http://localhost:8080

Write services.yml yourself for your lab IPs (a template is written on first run if missing).
This is a defender's own monitoring tool: it only connects to services to confirm they answer,
exactly like an uptime monitor. It does not log in or send payloads.

Checks supported: icmp, tcp, http, https, dns, ssh, ftp, mysql, ldap, winrm, rdp, smb.
Most are "does it answer": a TCP connect, an HTTP status < 500, a real DNS answer, an SSH/FTP/MySQL
banner. Good enough to mirror uptime scoring and catch self-inflicted outages.
"""
import argparse, socket, ssl, struct, subprocess, sys, threading, time, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

TEMPLATE = """# scorebot services - edit for your lab. One block per scored service.
# host is an IP or name reachable from where scorebot runs.
# Spring '26 scored services are pre-filled; change the IPs (X = your team number).
- name: pfSense ICMP         # Router
  host: 172.16.21.1
  check: icmp
- name: pfSense DNS
  host: 172.16.21.1
  check: dns
  query: dog.local           # a name the resolver should answer
- name: Gitlab ICMP
  host: 172.16.21.10
  check: icmp
- name: Gitlab SSH
  host: 172.16.21.10
  check: ssh
- name: Gitlab HTTP
  host: 172.16.21.10
  check: http
  path: /users/sign_in
- name: Comms ICMP
  host: 172.16.21.11
  check: icmp
- name: Comms SSH
  host: 172.16.21.11
  check: ssh
- name: Comms Mattermost
  host: 172.16.21.11
  check: http
  port: 8065
  path: /api/v4/system/ping
- name: Web ICMP
  host: 172.16.21.12
  check: icmp
- name: Web SSH
  host: 172.16.21.12
  check: ssh
- name: Web HTTP
  host: 172.16.21.12
  check: http
- name: Web MySQL
  host: 172.16.21.12
  check: mysql
- name: File ICMP
  host: 172.16.21.13
  check: icmp
- name: File SSH
  host: 172.16.21.13
  check: ssh
- name: File FTP
  host: 172.16.21.13
  check: ftp
- name: File ZeroClaw
  host: 172.16.21.13
  check: http
  port: 42617
  path: /health
- name: DC1 ICMP
  host: 172.16.21.5
  check: icmp
- name: DC1 LDAP
  host: 172.16.21.5
  check: tcp
  port: 389
- name: DC1 WinRM
  host: 172.16.21.5
  check: tcp
  port: 5985
- name: DC1 RDP
  host: 172.16.21.5
  check: tcp
  port: 3389
- name: DC2 ICMP
  host: 172.16.21.6
  check: icmp
- name: DC2 IIS
  host: 172.16.21.6
  check: http
- name: DC2 RDP
  host: 172.16.21.6
  check: tcp
  port: 3389
"""

DEFAULT_PORTS = {'http':80,'https':443,'ssh':22,'ftp':21,'mysql':3306,'ldap':389,
                 'winrm':5985,'rdp':3389,'smb':445,'dns':53}

def load_yaml(path):
    """Tiny YAML-ish loader for a flat list of 'key: value' blocks starting with '- '.
    Avoids a PyYAML dependency so this runs on a bare box."""
    items, cur = [], None
    for raw in open(path, encoding='utf-8'):
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith('- '):
            if cur:
                items.append(cur)
            cur = {}
            line = line.lstrip()[2:]
            if not line.strip():
                continue
        if ':' in line and cur is not None:
            k, v = line.strip().split(':', 1)
            cur[k.strip()] = v.strip()
    if cur:
        items.append(cur)
    return items

# ---- individual checks: return (up: bool, detail: str) --------------------
def c_icmp(s):
    n = '-n' if sys.platform.startswith('win') else '-c'
    w = '-w' if sys.platform.startswith('win') else '-W'
    try:
        r = subprocess.run(['ping', n, '1', w, '2', s['host']],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return r.returncode == 0, 'reply' if r.returncode == 0 else 'no reply'
    except Exception as e:
        return False, str(e)

def _connect(host, port, timeout=4):
    with socket.create_connection((host, port), timeout=timeout) as s:
        return s.recv(256)

def c_tcp(s):
    port = int(s.get('port', DEFAULT_PORTS.get(s['check'], 0)))
    try:
        socket.create_connection((s['host'], port), timeout=4).close()
        return True, f'{port} open'
    except Exception as e:
        return False, f'{port}: {e.__class__.__name__}'

def c_banner(s, default_port, want=b''):
    port = int(s.get('port', default_port))
    try:
        b = _connect(s['host'], port)
        if want and want not in b:
            return False, f'bad banner: {b[:30]!r}'
        return True, (b[:40].decode('latin1').strip() or f'{port} open')
    except Exception as e:
        return False, f'{port}: {e.__class__.__name__}'

def c_http(s):
    scheme = 'https' if s['check'] == 'https' else 'http'
    port = int(s.get('port', 443 if scheme == 'https' else 80))
    url = f"{scheme}://{s['host']}:{port}{s.get('path','/')}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urlopen(Request(url, headers={'User-Agent': 'scorebot'}),
                    timeout=5, context=ctx)
        code = r.getcode()
        return code < 500, f'HTTP {code}'
    except HTTPError as e:
        return e.code < 500, f'HTTP {e.code}'   # 401/403 still means the service is up
    except Exception as e:
        return False, e.__class__.__name__

def c_dns(s):
    """Minimal DNS A-record query over UDP. up = we got an answer with >=1 record."""
    port = int(s.get('port', 53))
    qname = s.get('query', s['host'])
    tid = os.getpid() & 0xFFFF
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    q = b''.join(bytes([len(p)]) + p.encode() for p in qname.split('.')) + b'\x00'
    pkt = header + q + struct.pack('>HH', 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.settimeout(4)
            u.sendto(pkt, (s['host'], port))
            data, _ = u.recvfrom(512)
        ancount = struct.unpack('>H', data[6:8])[0]
        rcode = data[3] & 0x0F
        return (rcode == 0 and ancount >= 1), f'ANCOUNT={ancount} RCODE={rcode}'
    except Exception as e:
        return False, e.__class__.__name__

CHECKS = {
    'icmp': c_icmp, 'tcp': c_tcp, 'http': c_http, 'https': c_http, 'dns': c_dns,
    'ssh':   lambda s: c_banner(s, 22, b'SSH'),
    'ftp':   lambda s: c_banner(s, 21, b'220'),
    'mysql': lambda s: c_banner(s, 3306),   # mysql greets with a version packet
    'ldap':  lambda s: c_tcp({**s, 'port': s.get('port', 389)}),
    'winrm': lambda s: c_tcp({**s, 'port': s.get('port', 5985)}),
    'rdp':   lambda s: c_tcp({**s, 'port': s.get('port', 3389)}),
    'smb':   lambda s: c_tcp({**s, 'port': s.get('port', 445)}),
}

STATE = {}           # name -> dict(up, detail, since, up_count, total, last)
LOCK = threading.Lock()

def run_check(svc):
    fn = CHECKS.get(svc['check'])
    if not fn:
        return False, f"unknown check {svc['check']}"
    try:
        return fn(svc)
    except Exception as e:
        return False, str(e)

def poller(services, interval):
    while True:
        start = time.time()
        for svc in services:
            up, detail = run_check(svc)
            with LOCK:
                st = STATE.setdefault(svc['name'], {'up': None, 'since': start, 'up_count': 0, 'total': 0})
                if st['up'] != up:
                    st['since'] = start
                st.update(up=up, detail=detail, last=start)
                st['total'] += 1
                if up:
                    st['up_count'] += 1
        time.sleep(max(1, interval - (time.time() - start)))

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>DOG Scorebot</title><meta http-equiv=refresh content=5>
<style>
 body{{background:#0b0f14;color:#e6edf3;font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px}}
 h1{{font-size:18px;margin:0 0 4px}} .sub{{color:#7d8590;margin-bottom:16px}}
 table{{border-collapse:collapse;width:100%;max-width:760px}}
 th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #1b222b}}
 .up{{color:#3fb950}} .down{{color:#f85149;font-weight:600}}
 .pill{{display:inline-block;min-width:52px;text-align:center;border-radius:10px;padding:2px 8px}}
 .pup{{background:#12361f;color:#3fb950}} .pdown{{background:#3a1416;color:#f85149}}
 .bar{{height:6px;background:#1b222b;border-radius:3px;overflow:hidden;width:120px}}
 .bar>i{{display:block;height:100%;background:#3fb950}}
 .det{{color:#7d8590;font-size:12px}}
</style></head><body>
<h1>DOG Scorebot</h1><div class=sub>every {interval}s &middot; {up}/{total} services up &middot; overall uptime {pct:.1f}%</div>
<table><tr><th>Service</th><th>Status</th><th>Uptime</th><th>Detail</th><th>Since</th></tr>
{rows}
</table></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        with LOCK:
            items = sorted(STATE.items())
            up = sum(1 for _, s in items if s['up'])
            total = len(items)
            gpct = 100 * sum(s['up_count'] for _, s in items) / max(1, sum(s['total'] for _, s in items))
            rows = []
            now = time.time()
            for name, s in items:
                pct = 100 * s['up_count'] / max(1, s['total'])
                cls = 'pup' if s['up'] else 'pdown'
                txt = 'UP' if s['up'] else 'DOWN'
                dur = int(now - s['since'])
                rows.append(
                    f"<tr><td>{name}</td>"
                    f"<td><span class='pill {cls}'>{txt}</span></td>"
                    f"<td><div class=bar><i style='width:{pct:.0f}%'></i></div> {pct:.0f}%</td>"
                    f"<td class=det>{s.get('detail','')}</td>"
                    f"<td class=det>{dur}s</td></tr>")
        body = PAGE.format(interval=self.server.interval, up=up, total=total,
                           pct=gpct, rows='\n'.join(rows)).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='services.yml')
    ap.add_argument('--interval', type=int, default=30)
    ap.add_argument('--port', type=int, default=8080)
    a = ap.parse_args()
    if not os.path.exists(a.config):
        open(a.config, 'w', encoding='utf-8').write(TEMPLATE)
        print(f"Wrote template {a.config} - edit the IPs for your lab, then rerun.")
        return
    services = load_yaml(a.config)
    for s in services:
        if 'name' not in s or 'host' not in s or 'check' not in s:
            print(f"Bad entry (needs name/host/check): {s}", file=sys.stderr)
            sys.exit(1)
    print(f"Scoring {len(services)} services every {a.interval}s. Scoreboard: http://localhost:{a.port}")
    threading.Thread(target=poller, args=(services, a.interval), daemon=True).start()
    httpd = ThreadingHTTPServer(('0.0.0.0', a.port), Handler)
    httpd.interval = a.interval
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")

if __name__ == '__main__':
    main()
