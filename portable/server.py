#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
777 Subscribers - portable launcher (works from a USB flash drive).

Serves the same index.html used by the Android app and acts as a small local
proxy to RadiusManager (a plain web page cannot talk to Radius directly because
of CORS / cookies).  Only Python's standard library is used.

  python server.py                -> starts the server and opens an app window
  python server.py --no-browser   -> only starts the server

Data (browser profile with settings, log, favourites, prices ...) is stored in
the "data" folder next to this script / the .exe, so it travels with the USB.
"""
import argparse
import http.client
import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FROZEN = bool(getattr(sys, 'frozen', False))
HERE = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
BUNDLE = getattr(sys, '_MEIPASS', HERE)
HOST = '127.0.0.1'
MAX_BODY = 8 * 1024 * 1024
SIGNATURE = 'ok-777-subscribers'

STATE = {'token': secrets.token_urlsafe(24), 'last_ping': None, 'started': time.time(),
         'page': None, 'port': 8777, 'allow_public': False}

SHIM = """<script>
(function () {
  if (window.Capacitor) return;
  var T = '%TOKEN%';
  window.Capacitor = {
    isNativePlatform: function () { return true; },
    getPlatform: function () { return 'portable'; },
    Plugins: { CapacitorHttp: { request: function (o) {
      return fetch('/__radius', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-777-Token': T },
        body: JSON.stringify({ url: o.url, method: o.method || 'GET', headers: o.headers || {}, data: (o.data == null ? null : String(o.data)) })
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok || j.error) throw new Error(j.error || ('proxy ' + r.status));
          return j;
        });
      });
    } } }
  };
  function ping() { fetch('/__ping', { cache: 'no-store' }).catch(function () {}); }
  ping(); setInterval(ping, 20000);
})();
</script>
"""


def log(*a):
    try:
        print(*a, flush=True)
    except Exception:
        pass


def find_page(arg):
    cands = []
    if arg:
        cands.append(arg)
    cands += [os.path.join(HERE, 'index.html'),
              os.path.join(HERE, '..', 'www', 'index.html'),
              os.path.join(BUNDLE, 'index.html')]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None


def load_page():
    with open(STATE['page'], 'r', encoding='utf-8') as f:
        html = f.read()
    shim = SHIM.replace('%TOKEN%', STATE['token'])
    low = html.lower()
    i = low.find('<head>')
    if i >= 0:
        j = i + len('<head>')
        return html[:j] + '\n' + shim + html[j:]
    return shim + html


def is_local_host(host):
    """Radius lives on the LAN: refuse to proxy to public addresses (SSRF safety)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return False
    return True


def decode_body(raw, ctype):
    cs = None
    if ctype and 'charset=' in ctype.lower():
        cs = ctype.lower().split('charset=')[1].split(';')[0].strip().strip('"\'')
    for enc in ([cs] if cs else []) + ['utf-8']:
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin-1', 'replace')


def forward(spec):
    u = urllib.parse.urlsplit(str(spec.get('url', '')))
    if u.scheme not in ('http', 'https') or not u.hostname:
        raise ValueError('bad url')
    if not STATE['allow_public'] and not is_local_host(u.hostname):
        raise PermissionError('target is not a local network address')
    https = u.scheme == 'https'
    port = u.port or (443 if https else 80)
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    if https:
        conn = http.client.HTTPSConnection(u.hostname, port, timeout=30, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(u.hostname, port, timeout=30)
    headers = {}
    for k, v in (spec.get('headers') or {}).items():
        if str(k).lower() in ('host', 'content-length', 'accept-encoding', 'connection', 'origin', 'referer'):
            continue
        headers[str(k)] = str(v)
    headers.setdefault('User-Agent', 'Mozilla/5.0 (777-Subscribers portable)')
    headers['Accept-Encoding'] = 'identity'
    method = str(spec.get('method') or 'GET').upper()
    body = spec.get('data')
    body_b = body.encode('utf-8') if isinstance(body, str) else None
    try:
        conn.request(method, path, body=body_b, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {}
        for k, v in resp.getheaders():
            if k.lower() != 'set-cookie':
                hdrs[k.lower()] = v
        cookies = resp.msg.get_all('Set-Cookie') or []
        if cookies:
            hdrs['set-cookie'] = ', '.join(cookies)
        return {'status': resp.status, 'headers': hdrs, 'data': decode_body(raw, resp.getheader('Content-Type')), 'url': spec.get('url')}
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = '777Portable/1.0'

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='text/plain; charset=utf-8'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        h = (self.headers.get('Host') or '').lower()
        p = STATE['port']
        return h in ('127.0.0.1:%d' % p, 'localhost:%d' % p)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/__ping':
            STATE['last_ping'] = time.time()
            return self._send(200, SIGNATURE)
        if not self._host_ok():
            return self._send(403, 'forbidden host')
        if path in ('/', '/index.html'):
            try:
                return self._send(200, load_page(), 'text/html; charset=utf-8')
            except Exception as e:
                return self._send(500, 'cannot read page: %s' % e)
        return self._send(404, 'not found')

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path != '/__radius':
            return self._send(404, 'not found')
        if not self._host_ok():
            return self._send(403, 'forbidden host')
        if self.headers.get('X-777-Token') != STATE['token']:
            return self._send(403, 'bad token')
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n < 0 or n > MAX_BODY:
                return self._send(413, 'too large')
            spec = json.loads(self.rfile.read(n).decode('utf-8'))
            STATE['last_ping'] = time.time()
            out = forward(spec)
            return self._send(200, json.dumps(out, ensure_ascii=False), 'application/json; charset=utf-8')
        except PermissionError as e:
            return self._send(403, json.dumps({'error': str(e)}), 'application/json')
        except (socket.timeout, TimeoutError):
            return self._send(502, json.dumps({'error': 'timeout while contacting Radius'}), 'application/json')
        except Exception as e:
            return self._send(502, json.dumps({'error': '%s: %s' % (type(e).__name__, e)}, ensure_ascii=False), 'application/json')


def ping(port):
    try:
        c = http.client.HTTPConnection(HOST, port, timeout=1.5)
        c.request('GET', '/__ping', headers={'Host': '%s:%d' % (HOST, port)})
        r = c.getresponse()
        ok = r.status == 200 and r.read().decode('utf-8', 'replace') == SIGNATURE
        c.close()
        return ok
    except Exception:
        return False


def find_browser():
    c = []
    if sys.platform.startswith('win'):
        for env in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA'):
            base = os.environ.get(env)
            if not base:
                continue
            for rel in (r'Microsoft\Edge\Application\msedge.exe', r'Google\Chrome\Application\chrome.exe',
                        r'BraveSoftware\Brave-Browser\Application\brave.exe', r'Chromium\Application\chrome.exe'):
                c.append(os.path.join(base, rel))
    elif sys.platform == 'darwin':
        for app in ('Google Chrome', 'Microsoft Edge', 'Brave Browser', 'Chromium'):
            c.append('/Applications/%s.app/Contents/MacOS/%s' % (app, app))
    else:
        for name in ('google-chrome', 'google-chrome-stable', 'microsoft-edge', 'chromium', 'chromium-browser', 'brave-browser'):
            p = shutil.which(name)
            if p:
                c.append(p)
    for p in c:
        if p and os.path.isfile(p):
            return p
    return None


def data_dir():
    d = os.path.join(HERE, 'data')
    try:
        os.makedirs(os.path.join(d, 'profile'), exist_ok=True)
        t = os.path.join(d, '.w')
        with open(t, 'w') as f:
            f.write('1')
        os.remove(t)
        return d
    except Exception:
        d = os.path.join(tempfile.gettempdir(), '777-subscribers-data')
        os.makedirs(os.path.join(d, 'profile'), exist_ok=True)
        log('NOTE: USB is read-only, data will be stored in', d)
        return d


def open_app(url):
    b = find_browser()
    if b:
        prof = os.path.join(data_dir(), 'profile')
        try:
            subprocess.Popen([b, '--app=' + url, '--user-data-dir=' + prof, '--no-first-run',
                              '--no-default-browser-check', '--window-size=1200,850'])
            return
        except Exception as e:
            log('Could not start browser app window:', e)
    webbrowser.open(url)


def watchdog(idle):
    while True:
        time.sleep(5)
        now = time.time()
        lp = STATE['last_ping']
        if (lp is not None and now - lp > idle) or (lp is None and now - STATE['started'] > max(idle, 180)):
            log('Window closed - bye.')
            os._exit(0)


def main():
    ap = argparse.ArgumentParser(description='777 Subscribers portable launcher')
    ap.add_argument('--port', type=int, default=8777)
    ap.add_argument('--page', default=None, help='path to index.html')
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--idle-timeout', type=int, default=150, help='seconds without the page before the server exits')
    ap.add_argument('--allow-public', action='store_true', help='allow proxying to non-local addresses (not recommended)')
    a = ap.parse_args()

    page = find_page(a.page)
    if not page:
        log('ERROR: index.html not found next to this program.')
        return 1
    STATE['page'] = page
    STATE['allow_public'] = a.allow_public

    srv = None
    for port in range(a.port, a.port + 10):
        if ping(port):
            url = 'http://%s:%d/' % (HOST, port)
            log('Already running at', url)
            if not a.no_browser:
                open_app(url)
            return 0
        try:
            srv = ThreadingHTTPServer((HOST, port), Handler)
            STATE['port'] = port
            break
        except OSError:
            continue
    if srv is None:
        log('ERROR: no free port between %d and %d.' % (a.port, a.port + 9))
        return 1
    url = 'http://%s:%d/' % (HOST, STATE['port'])
    log('777 Subscribers is running at', url)
    log('Page:', page)
    log('Close the app window to stop (or close this window).')
    threading.Thread(target=watchdog, args=(a.idle_timeout,), daemon=True).start()
    if not a.no_browser:
        open_app(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    try:
        code = main()
    except Exception as e:
        log('FATAL:', e)
        code = 1
    if code and FROZEN:
        try:
            input('Press Enter to close...')
        except Exception:
            pass
    sys.exit(code)
