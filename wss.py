"""Small RFC 6455 SIP-over-WSS client using only Python's standard library.

TLS is verified with system/custom CAs, or with an explicitly configured
SHA-256 certificate pin obtained through a trusted channel.
"""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import os
import ssl
import struct
from urllib.parse import urlsplit

LIMIT = 256 * 1024
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def frame(data, opcode=1):
    if len(data) > LIMIT:
        raise ValueError('WebSocket message too large')
    mask = os.urandom(4)
    n = len(data)
    header = bytes([0x80 | opcode])
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += b'\xfe' + struct.pack('!H', n)
    else:
        header += b'\xff' + struct.pack('!Q', n)
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


class WSS:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.cfg = endpoint.cfg
        self.writer = self.reader = None
        self.reader_task = self.ping_task = None
        self.lock = asyncio.Lock()
        self.closed = False
        self.generation = 0
        self.pong = asyncio.Event()

    async def connect(self):
        async with self.lock:
            if self.writer and not self.writer.is_closing():
                return
            if self.closed:
                raise OSError('WSS transport is closed')
            parsed = urlsplit(self.cfg['wss_url'])
            if parsed.scheme != 'wss' or not parsed.hostname or parsed.username or parsed.fragment:
                raise ValueError('sip.wss_url must be a wss://host:port/path URL')
            pin = self.cfg.get('tls_cert_sha256', '').replace(':', '').lower()
            if pin:
                if len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
                    raise ValueError('Invalid TLS certificate SHA-256 pin')
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = ssl.create_default_context(cafile=self.cfg.get('tls_ca_file') or None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                parsed.hostname, parsed.port or 443, ssl=context, server_hostname=parsed.hostname), 10)
            try:
                if pin:
                    der = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
                    if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), pin):
                        raise ssl.SSLError('FreeSWITCH TLS certificate pin mismatch; refusing to send SIP credentials')
                key = base64.b64encode(os.urandom(16)).decode()
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
                if any(c in path for c in '\r\n '):
                    raise ValueError('Invalid WSS path')
                host = parsed.hostname + (f':{parsed.port}' if parsed.port else '')
                request = (f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n'
                           f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
                           'Sec-WebSocket-Protocol: sip\r\n\r\n')
                writer.write(request.encode('ascii')); await writer.drain()
                head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
                if len(head) > 16384:
                    raise ValueError('WSS response headers too large')
                lines = head.decode('latin1').split('\r\n')
                if len(lines[0].split()) < 2 or lines[0].split()[1] != '101':
                    raise OSError('WebSocket handshake failed: ' + lines[0])
                headers = {k.strip().lower(): v.strip() for line in lines[1:] if ':' in line
                           for k, v in [line.split(':', 1)]}
                accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
                if headers.get('sec-websocket-accept') != accept or headers.get('sec-websocket-protocol') != 'sip':
                    raise OSError('Invalid SIP WebSocket handshake')
                if headers.get('upgrade', '').lower() != 'websocket' or 'upgrade' not in headers.get('connection', '').lower():
                    raise OSError('Missing WebSocket Upgrade headers')
                self.reader, self.writer = reader, writer
                self.generation += 1
                self.reader_task = asyncio.create_task(self.read_loop(reader, writer))
                self.ping_task = asyncio.create_task(self.ping_loop(writer))
                self.endpoint.log('WSS connected (TLS certificate verified)')
            except BaseException:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 2)
                raise

    def sendto(self, data, addr=None):
        if not self.writer or self.writer.is_closing():
            raise OSError('WSS connection is not open')
        if self.writer.transport.get_write_buffer_size() > LIMIT * 4:
            raise OSError('WSS send buffer is full')
        self.writer.write(frame(data))

    async def read_loop(self, reader, writer):
        fragments = bytearray()
        fragmented_opcode = None
        try:
            while True:
                first, second = await reader.readexactly(2)
                final, opcode = bool(first & 128), first & 15
                if first & 112 or second & 128:
                    raise ValueError('Unexpected reserved bits / masked server frame')
                length = second & 127
                if length == 126:
                    length = struct.unpack('!H', await reader.readexactly(2))[0]
                elif length == 127:
                    length = struct.unpack('!Q', await reader.readexactly(8))[0]
                if length > LIMIT or (opcode >= 8 and (length > 125 or not final)):
                    raise ValueError('Invalid WebSocket frame length')
                data = await reader.readexactly(length)
                if opcode == 8:
                    writer.write(frame(data[:125], 8)); await writer.drain()
                    return
                if opcode == 9:
                    writer.write(frame(data, 10)); await writer.drain()
                    continue
                if opcode == 10:
                    if data == b'miniphone':
                        self.pong.set()
                    continue
                if opcode in (1, 2):
                    if fragmented_opcode is not None:
                        raise ValueError('Overlapping fragmented WebSocket messages')
                    fragmented_opcode = opcode
                elif opcode != 0 or fragmented_opcode is None:
                    raise ValueError('Invalid WebSocket continuation')
                fragments.extend(data)
                if len(fragments) > LIMIT:
                    raise ValueError('WebSocket SIP message too large')
                if final:
                    if fragmented_opcode == 1:
                        fragments.decode('utf-8')
                    self.endpoint.datagram_received(bytes(fragments), (self.cfg['server_ip'], self.cfg['port']))
                    fragments.clear(); fragmented_opcode = None
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, asyncio.IncompleteReadError) as exc:
            if not self.closed:
                self.endpoint.log(f'WSS disconnected: {exc}')
        finally:
            writer.close()
            if self.writer is writer:
                self.writer = None
                if self.ping_task:
                    self.ping_task.cancel()
                for queue in self.endpoint.pending.values():
                    queue.put_nowait(OSError('WSS connection lost'))
                if self.endpoint.on_disconnect and not self.closed:
                    self.endpoint.on_disconnect()

    async def ping_loop(self, writer):
        try:
            while not writer.is_closing():
                await asyncio.sleep(20)
                self.pong.clear()
                writer.write(frame(b'miniphone', 9))
                await writer.drain()
                await asyncio.wait_for(self.pong.wait(), 15)
        except asyncio.CancelledError:
            pass
        except (OSError, TimeoutError):
            writer.close()

    async def shutdown(self):
        self.closed = True
        if self.writer:
            self.writer.close()
        tasks = [t for t in (self.reader_task, self.ping_task) if t]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

