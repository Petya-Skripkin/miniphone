"""SIP/UDP transport, transactions and Digest auth. No external Python packages."""
import asyncio
import hashlib
import re
import secrets
import socket
import time
from dataclasses import dataclass

ALIASES = {'v': 'via', 'f': 'from', 't': 'to', 'i': 'call-id', 'm': 'contact',
           'l': 'content-length', 'c': 'content-type'}


def token():
    return secrets.token_hex(12)


def uri(value):
    match = re.search(r'<([^>]+)>', value)
    return match[1] if match else value.strip().split(';tag=')[0]


def tag(value):
    m = re.search(r'(?:^|;)\s*tag=([^;\s]+)', value)
    return m[1] if m else ''


def destination(value):
    value = uri(value)
    if not value.lower().startswith('sip:'):
        raise ValueError('Only sip: IPv4/UDP URIs are supported')
    value = value[4:]
    transport = re.search(r';transport=([^;?]+)', value, re.I)
    if transport and transport[1].lower() != 'udp':
        raise ValueError('Only UDP transport is supported')
    host = value.split(';')[0].split('?')[0].rsplit('@', 1)[-1]
    if ':' in host:
        host, port = host.rsplit(':', 1)
        port = int(port)
    else:
        port = 5060
    if not host or not 1 <= port <= 65535:
        raise ValueError('Invalid SIP destination')
    return socket.gethostbyname(host), port


@dataclass
class Message:
    first: str
    headers: list
    body: str = ''

    @classmethod
    def parse(cls, data):
        if len(data) > 65507:
            raise ValueError('SIP datagram too large')
        head, sep, body = data.partition(b'\r\n\r\n')
        if not sep:
            raise ValueError('Invalid SIP message')
        lines = head.decode('utf-8', 'replace').split('\r\n')
        headers = []
        for line in lines[1:]:
            if line.startswith((' ', '\t')) and headers:
                key, value = headers[-1]
                headers[-1] = key, value + ' ' + line.strip()
                continue
            key, colon, value = line.partition(':')
            if not colon:
                raise ValueError('Invalid SIP header')
            headers.append((ALIASES.get(key.lower(), key), value.strip()))
        msg = cls(lines[0], headers)
        length = int(msg.get('Content-Length', str(len(body))))
        if length < 0 or length > len(body):
            raise ValueError('Invalid SIP Content-Length')
        msg.body = body[:length].decode('utf-8', 'replace')
        if not all(msg.get(k) for k in ['Via', 'From', 'To', 'Call-ID', 'CSeq']):
            raise ValueError('Missing SIP headers')
        return msg

    def get(self, key, default=''):
        return next((v for k, v in self.headers if k.lower() == key.lower()), default)

    def all(self, key):
        return [v for k, v in self.headers if k.lower() == key.lower()]

    def set(self, key, value):
        self.headers = [(k, v) for k, v in self.headers if k.lower() != key.lower()]
        self.headers.append((key, value))

    @property
    def status(self):
        return int(self.first.split()[1]) if self.first.startswith('SIP/2.0 ') else 0

    @property
    def method(self):
        return self.first.split()[0]

    @property
    def key(self):
        branch = re.search(r'(?:^|;)\s*branch=([^;\s]+)', self.get('Via'))
        return (branch[1] if branch else self.get('Via'), self.get('Call-ID'), self.get('CSeq'))

    def wire(self):
        body = self.body.encode('utf-8')
        headers = [(k, v) for k, v in self.headers if k.lower() != 'content-length']
        for key, value in headers:
            if '\r' in value or '\n' in value:
                raise ValueError('Newline in SIP header')
        return (self.first + '\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in headers)
                + f'Content-Length: {len(body)}\r\n\r\n').encode('utf-8') + body


def digest(challenge, username, password, method, target, nc=1):
    if not challenge.lower().startswith('digest '):
        raise ValueError('Server requested unsupported authentication')
    fields = {m[1].lower(): (m[2] if m[2] is not None else m[3])
              for m in re.finditer(r'(\w[\w-]*)\s*=\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^,\s]+))', challenge[7:])}
    realm, nonce = fields['realm'], fields['nonce']
    algorithm = fields.get('algorithm', 'MD5').upper()
    base = algorithm.removesuffix('-SESS')
    if base not in ('MD5', 'SHA-256'):
        raise ValueError(f'Unsupported Digest algorithm: {algorithm}')
    def h(s):
        return hashlib.new(base.lower().replace('-', ''), s.encode('utf-8')).hexdigest()
    def quote(s):
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    cnonce, count = token(), f'{nc:08x}'
    ha1 = h(f'{username}:{realm}:{password}')
    if algorithm.endswith('-SESS'):
        ha1 = h(f'{ha1}:{nonce}:{cnonce}')
    ha2 = h(f'{method}:{target}')
    qops = [q.strip().lower() for q in fields.get('qop', '').split(',') if q.strip()]
    if qops and 'auth' not in qops:
        raise ValueError('Only Digest qop=auth is supported')
    response = h(f'{ha1}:{nonce}:{count}:{cnonce}:auth:{ha2}') if qops else h(f'{ha1}:{nonce}:{ha2}')
    out = [f'username={quote(username)}', f'realm={quote(realm)}', f'nonce={quote(nonce)}',
           f'uri={quote(target)}', f'response={quote(response)}', f'algorithm={algorithm}']
    if qops:
        out += ['qop=auth', f'nc={count}', f'cnonce={quote(cnonce)}']
    elif algorithm.endswith('-SESS'):
        out += [f'cnonce={quote(cnonce)}']
    if 'opaque' in fields:
        out += [f'opaque={quote(fields["opaque"])}']
    return 'Digest ' + ', '.join(out)


class Endpoint(asyncio.DatagramProtocol):
    def __init__(self, cfg, log=print):
        self.cfg, self.log = cfg, log
        self.transport = None
        self.pending, self.cache, self.acks = {}, {}, {}
        self.handler = None
        self.on_disconnect = None
        self.reliable = cfg.get('transport') == 'wss'
        self.tasks = set()

    async def start(self):
        if self.reliable:
            from wss import WSS
            self.transport = WSS(self)
            try:
                await self.transport.connect()
            except (OSError, ValueError, TimeoutError) as exc:
                self.log(f'WSS initial connection: {exc}; registration will retry')
            return
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: self,
            local_addr=(self.cfg['bind'], self.cfg['local_port']), family=socket.AF_INET)

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        self.log(f'SIP socket: {exc}')

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        def finished(t):
            if not t.cancelled() and t.exception():
                self.log(f'SIP handler error: {t.exception()}')
        task.add_done_callback(finished)
        return task

    def datagram_received(self, data, addr):
        if data.strip() == b'':
            if data == b'\r\n\r\n':
                self.transport.sendto(b'\r\n', addr)
            return
        try:
            msg = Message.parse(data)
            now = time.monotonic()
            self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
            self.acks = {k: v for k, v in self.acks.items() if v[0] > now}
            if msg.status:
                key = (msg.get('Call-ID'), msg.get('CSeq'), tag(msg.get('To')))
                if key in self.acks and msg.status >= 200:
                    _, ack, dest = self.acks[key]
                    self.send(ack, dest)
                elif msg.key in self.pending:
                    self.pending[msg.key].put_nowait(msg)
            elif msg.key in self.cache and msg.method != 'ACK':
                self.transport.sendto(self.cache[msg.key][1], addr)
            elif self.handler:
                self.spawn(self.handler(msg, addr))
        except (ValueError, IndexError, KeyError) as exc:
            self.log(f'Ignored malformed SIP from {addr[0]}: {exc}')

    def send(self, msg, addr):
        self.transport.sendto(msg.wire(), addr)

    def request(self, method, target, call_id=None, seq=1, from_value=None, to_value=None,
                body='', branch=None, extra=()):
        s = self.cfg
        identity = f'sip:{s["username"]}@{s["domain"]}'
        protocol = 'WSS' if self.reliable else 'UDP'
        contact_transport = ';transport=ws' if self.reliable else ''
        return Message(f'{method} {target} SIP/2.0', [
            ('Via', f'SIP/2.0/{protocol} {s["advertise_ip"]}:{s["local_port"]};branch={branch or "z9hG4bK" + token()};rport'),
            ('Max-Forwards', '70'), ('From', from_value or f'<{identity}>;tag={token()}'),
            ('To', to_value or f'<{target}>'), ('Call-ID', call_id or token() + '@' + s['advertise_ip']),
            ('CSeq', f'{seq} {method}'), ('Contact', f'<sip:{s["username"]}@{s["advertise_ip"]}:{s["local_port"]}{contact_transport}>'),
            ('User-Agent', 'MiniPhone/0.1'), ('Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS')
        ] + list(extra) + ([('Content-Type', 'application/sdp')] if body else []), body)

    def respond(self, req, addr, code, reason, local_tag='', body='', extra=()):
        headers = []
        for index, via in enumerate(req.all('Via')):
            if index == 0:
                via = re.sub(r';rport(?:=\d+)?(?=;|$)', f';rport={addr[1]}', via)
                via = re.sub(r';received=[^;]+', '', via) + f';received={addr[0]}'
            headers.append(('Via', via))
        to = req.get('To')
        if code > 100 and not tag(to):
            to += ';tag=' + (local_tag or token())
        headers += [('From', req.get('From')), ('To', to), ('Call-ID', req.get('Call-ID')),
                    ('CSeq', req.get('CSeq')), ('User-Agent', 'MiniPhone/0.1')]
        if req.method == 'INVITE':
            suffix = ';transport=ws' if self.reliable else ''
            headers += [('Contact', f'<sip:{self.cfg["username"]}@{self.cfg["advertise_ip"]}:{self.cfg["local_port"]}{suffix}>')]
            headers += [('Record-Route', r) for r in req.all('Record-Route')]
        if body:
            headers += [('Content-Type', 'application/sdp')]
        msg = Message(f'SIP/2.0 {code} {reason}', headers + list(extra), body)
        wire = msg.wire()
        self.cache[req.key] = (time.monotonic() + 64, wire)
        self.transport.sendto(wire, addr)
        return msg

    def remember_ack(self, response, ack, addr):
        key = (response.get('Call-ID'), response.get('CSeq'), tag(response.get('To')))
        self.acks[key] = (time.monotonic() + 64, ack, addr)
        self.send(ack, addr)

    def failure_ack(self, req, response, addr):
        ack = Message(req.first.replace('INVITE ', 'ACK ', 1), list(req.headers))
        ack.set('CSeq', req.get('CSeq').split()[0] + ' ACK')
        ack.set('To', response.get('To'))
        ack.headers = [(k, v) for k, v in ack.headers if k.lower() != 'content-type']
        self.remember_ack(response, ack, addr)

    async def transact(self, req, addr, provisional=None, timeout=32):
        if self.reliable:
            await self.transport.connect()
        queue = asyncio.Queue()
        self.pending[req.key] = queue
        invite = req.method == 'INVITE'
        interval, received_provisional = .5, False
        end = time.monotonic() + timeout
        try:
            self.send(req, addr)
            while time.monotonic() < end:
                wait = end - time.monotonic() if self.reliable or (invite and received_provisional) else min(interval, end - time.monotonic())
                try:
                    response = await asyncio.wait_for(queue.get(), wait)
                except asyncio.TimeoutError:
                    if not self.reliable and not (invite and received_provisional):
                        self.send(req, addr)
                        interval = min(interval * 2, 4)
                    continue
                if isinstance(response, Exception):
                    raise response
                if response.status < 200:
                    received_provisional = True
                    if invite:
                        end = time.monotonic() + timeout
                    if provisional:
                        provisional(response)
                    continue
                if invite and response.status >= 300:
                    self.failure_ack(req, response, addr)
                return response
            raise TimeoutError(f'{req.method}: no final response')
        finally:
            self.pending.pop(req.key, None)

    async def authenticated(self, req, addr, provisional=None, on_request=None):
        for attempt in range(3):
            if on_request:
                on_request(req)
            response = await self.transact(req, addr, provisional)
            if response.status not in (401, 407):
                return response, req
            challenge_key = 'WWW-Authenticate' if response.status == 401 else 'Proxy-Authenticate'
            auth_key = 'Authorization' if response.status == 401 else 'Proxy-Authorization'
            value = digest(response.get(challenge_key), self.cfg['auth_username'], self.cfg['password'],
                           req.method, req.first.split()[1], attempt + 1)
            req = Message(req.first, list(req.headers), req.body)
            req.set(auth_key, value)
            number, method = req.get('CSeq').split()
            req.set('CSeq', f'{int(number) + 1} {method}')
            req.set('Via', re.sub(r'branch=[^;]+', 'branch=z9hG4bK' + token(), req.get('Via')))
        raise ValueError('SIP authentication rejected after 3 attempts')

    async def close(self):
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        if self.transport:
            if self.reliable:
                await self.transport.shutdown()
            else:
                self.transport.close()
