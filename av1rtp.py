"""AV1 RTP payloads (AOM AV1 RTP 1.0); single spatial/temporal layer.

Encoder sends one OBU/fragment per packet (W=1). Decoder accepts W=0..3,
fragmentation, extensions, padding and discards incomplete temporal units.
"""
import secrets
import struct

MAX_FRAME = 4 * 1024 * 1024


def leb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        out.append(byte | (128 if value else 0))
        if not value:
            return bytes(out)


def unleb(data, pos=0):
    value = 0
    for i in range(8):
        if pos >= len(data):
            raise ValueError('Truncated LEB128')
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << (7 * i)
        if not byte & 128:
            return value, pos
    raise ValueError('LEB128 too long')


def split_obus(data):
    pos, obus = 0, []
    while pos < len(data):
        head = data[pos]
        n = 2 if head & 4 else 1
        if head & 0x81 or pos + n > len(data):
            raise ValueError('Invalid OBU header')
        header = bytes([head & ~2]) + data[pos + 1:pos + n]
        pos += n
        if head & 2:
            size, pos = unleb(data, pos)
        else:
            size = len(data) - pos
        if size > MAX_FRAME or pos + size > len(data):
            raise ValueError('Invalid OBU length')
        if ((head >> 3) & 15) not in (2, 8, 15):
            obus.append(header + data[pos:pos + size])
        pos += size
    return obus


def sized_obu(data):
    if not data:
        raise ValueError('Empty OBU')
    n = 2 if data[0] & 4 else 1
    if len(data) < n:
        raise ValueError('Truncated OBU')
    if data[0] & 2:
        size, pos = unleb(data, n)
        if pos + size != len(data):
            raise ValueError('Invalid sized OBU')
        return data
    return bytes([data[0] | 2]) + data[1:n] + leb(len(data) - n) + data[n:]


class Payloader:
    def __init__(self, pt, mtu=1200):
        self.pt, self.mtu = pt, mtu
        self.seq = secrets.randbits(16)
        self.ssrc = secrets.randbits(32)
        self.base = secrets.randbits(32)

    def packets(self, data, pts_ns):
        obus = split_obus(data)
        timestamp = (self.base + pts_ns * 90000 // 1000000000) & 0xffffffff
        for index, obu in enumerate(obus):
            size = self.mtu - 13
            for pos in range(0, len(obu), size):
                fragment = obu[pos:pos + size]
                final = pos + len(fragment) == len(obu)
                aggr = 0x10 | (0x80 if pos else 0) | (0 if final else 0x40)
                if index == 0 and pos == 0 and (obu[0] >> 3) & 15 == 1:
                    aggr |= 8
                marker = final and index == len(obus) - 1
                header = struct.pack('!BBHII', 0x80, self.pt | (0x80 if marker else 0), self.seq, timestamp, self.ssrc)
                self.seq = (self.seq + 1) & 65535
                yield header + bytes([aggr]) + fragment


class Depayloader:
    def __init__(self):
        self.seq = self.timestamp = self.ssrc = None
        self.fragment = bytearray()
        self.frame = bytearray()
        self.bad = False

    def push(self, packet):
        if len(packet) < 13 or packet[0] >> 6 != 2:
            raise ValueError('Invalid RTP packet')
        seq, timestamp, ssrc = struct.unpack_from('!HII', packet, 2)
        pos = 12 + 4 * (packet[0] & 15)
        if packet[0] & 16:
            if pos + 4 > len(packet):
                raise ValueError('Truncated RTP extension')
            pos += 4 + 4 * struct.unpack_from('!H', packet, pos + 2)[0]
        end = len(packet)
        if packet[0] & 32:
            padding = packet[-1]
            if not padding or padding > end - pos:
                raise ValueError('Invalid RTP padding')
            end -= padding
        if pos >= end:
            raise ValueError('Empty RTP payload')
        completed = []
        if self.ssrc != ssrc:
            self.seq = self.timestamp = None
            self.frame.clear(); self.fragment.clear(); self.bad = False
            self.ssrc = ssrc
        gap = self.seq is not None and seq != (self.seq + 1) & 65535
        if self.timestamp != timestamp:
            if self.frame and not self.fragment and not self.bad and not gap:
                completed.append(bytes(self.frame))
            self.frame.clear(); self.fragment.clear(); self.bad = False
            self.timestamp = timestamp
        if gap:
            self.bad = True
            self.frame.clear(); self.fragment.clear()
        self.seq = seq
        data = packet[pos:end]
        z, y, w = bool(data[0] & 128), bool(data[0] & 64), (data[0] >> 4) & 3
        if data[0] & 8 and not z:
            self.bad = False
            self.frame.clear(); self.fragment.clear()
        cursor, elements = 1, []
        while cursor < len(data):
            if w and len(elements) == w - 1:
                size = len(data) - cursor
            else:
                size, cursor = unleb(data, cursor)
            if not size or cursor + size > len(data):
                raise ValueError('Invalid AV1 aggregation length')
            elements.append(data[cursor:cursor + size])
            cursor += size
        if not elements or (w and len(elements) != w):
            raise ValueError('Invalid AV1 aggregation count')
        if self.fragment and not z:
            self.bad = True
        for i, part in enumerate(elements):
            if i == 0 and z:
                if not self.fragment:
                    self.bad = True
                self.fragment.extend(part)
                part = bytes(self.fragment)
                self.fragment.clear()
            if i == len(elements) - 1 and y:
                self.fragment.extend(part)
            elif not self.bad:
                self.frame.extend(sized_obu(part))
        if len(self.frame) + len(self.fragment) > MAX_FRAME:
            self.frame.clear(); self.fragment.clear(); self.bad = True
            raise ValueError('AV1 temporal unit too large')
        if packet[1] & 128:
            if self.frame and not self.fragment and not self.bad:
                completed.append(bytes(self.frame))
            self.frame.clear(); self.fragment.clear(); self.bad = False
        return completed
