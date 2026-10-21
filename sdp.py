"""Small SDP offer/answer implementation for IPv4 RTP/AVP."""
import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from settings import AUDIO, VIDEO


@dataclass
class Stream:
    kind: str
    port: int
    proto: str
    pts: list
    ip: str = ''
    codecs: dict = field(default_factory=dict)
    fmtp: dict = field(default_factory=dict)
    direction: str = 'sendrecv'
    rtcp: int = 0


def parse(body):
    streams, current, ip, direction = [], None, '', 'sendrecv'
    for line in body.replace('\r', '').split('\n'):
        if line.startswith('m='):
            kind, port, proto, *pts = line[2:].split()
            current = Stream(kind, int(port.split('/')[0]), proto,
                             [int(p) for p in pts if p.isdigit()], ip, direction=direction)
            current.codecs = {pt: name for name, (pt, _) in AUDIO.items() if pt in current.pts}
            streams.append(current)
        elif line.startswith('c=IN IP4 '):
            address = str(ipaddress.IPv4Address(line.split()[2]))
            if current is None:
                ip = address
            else:
                current.ip = address
        elif line.startswith('a=rtpmap:') and current:
            pt, encoding = line[9:].split(None, 1)
            parts = encoding.split('/')
            name = parts[0].upper()
            spec = (AUDIO | VIDEO).get(name)
            if spec and int(parts[1]) == spec[1] and (len(parts) < 3 or parts[2] == '1'):
                current.codecs[int(pt)] = name
            else:
                current.codecs.pop(int(pt), None)
        elif line.startswith('a=fmtp:') and current:
            pt, _, value = line[7:].partition(' ')
            current.fmtp[int(pt)] = value
        elif line[2:] in ('sendrecv', 'sendonly', 'recvonly', 'inactive') and line.startswith('a='):
            if current:
                current.direction = line[2:]
            else:
                direction = line[2:]
        elif line.startswith('a=rtcp:') and current:
            # Explicit separate RTCP address is deliberately unsupported.
            fields = line[7:].split()
            if len(fields) > 1 and (fields[1:3] != ['IN', 'IP4'] or fields[3] != current.ip):
                raise ValueError('Separate RTCP host is unsupported')
            current.rtcp = int(fields[0])
    for s in streams:
        if not 0 <= s.port <= 65534 or not 0 <= s.rtcp <= 65535:
            raise ValueError('Invalid SDP port')
        if not s.ip:
            raise ValueError('SDP has no IPv4 connection address')
        if not s.rtcp:
            s.rtcp = s.port + 1
    return streams


def params(value):
    return dict((k.strip().lower(), v.strip()) for part in value.split(';')
                for k, sep, v in [part.partition('=')] if sep)


def compatible(name, fmtp):
    p = params(fmtp)
    if name == 'H264':
        # Baseline / constrained baseline, level 3.1, non-interleaved mode.
        profile = p.get('profile-level-id', '42001f').lower()
        return (bool(re.fullmatch('[0-9a-f]{6}', profile)) and profile[:2] == '42'
                and int(profile[4:], 16) == 31
                and p.get('packetization-mode', '0') == '1')
    if name == 'AV1':
        return p.get('profile', '0') == '0'
    return True


def choose(streams, cfg):
    selected = []
    seen = set()
    for s in streams:
        if s.kind not in ('audio', 'video') or s.kind in seen or not s.port:
            selected.append(None)
            continue
        seen.add(s.kind)
        allowed = cfg['media'][s.kind + '_codecs']
        if s.kind == 'video' and not cfg['media']['video']:
            allowed = []
        picked = None
        if s.proto == 'RTP/AVP':
            for name in allowed:
                for pt in s.pts:
                    if s.codecs.get(pt) == name and compatible(name, s.fmtp.get(pt, '')):
                        picked = (s, pt, name)
                        break
                if picked:
                    break
        selected.append(picked)
    if not any(x and x[0].kind == 'audio' for x in selected):
        raise ValueError('No common audio codec / supported RTP profile')
    return selected


def validate_answer(streams, offered_streams):
    if len(streams) != len(offered_streams):
        raise ValueError('SDP answer changed number of media sections')
    for answer, offered in zip(streams, offered_streams):
        if answer.kind != offered.kind:
            raise ValueError('SDP answer reordered media sections')
        if not answer.port:
            continue
        for pt in answer.pts:
            name = answer.codecs.get(pt)
            # Some PBXs append telephone-event even when it was not offered.
            # Unknown payloads are ignored, never announced, selected or decoded.
            if name is not None and (pt not in offered.pts or name != offered.codecs.get(pt)):
                raise ValueError('SDP answer selected an unoffered codec')


def codec_lines(name, pt, fmtp=''):
    lines = [f'a=rtpmap:{pt} {name}/{(AUDIO | VIDEO)[name][1]}']
    if name == 'H264':
        p = params(fmtp)
        mode = p.get('packetization-mode', '1')
        profile = p.get('profile-level-id', '42801f')
        lines.append(f'a=fmtp:{pt} packetization-mode={mode};profile-level-id={profile}')
    elif name == 'G729':
        lines.append(f'a=fmtp:{pt} annexb=no')
    elif name == 'AV1':
        lines.append(f'a=fmtp:{pt} profile=0;level-idx=5;tier=0')
    return lines


def make(cfg, selected=None, video=True, session=None):
    ip = cfg['sip']['advertise_ip']
    session = session or secrets.randbits(48)
    lines = ['v=0', f'o=- {session} {session} IN IP4 {ip}', 's=MiniPhone',
             f'c=IN IP4 {ip}', 't=0 0']
    if selected is None:
        for kind, table, offset in [('audio', AUDIO, 0), ('video', VIDEO, 2)]:
            if kind == 'video' and not (video and cfg['media']['video']):
                continue
            names = cfg['media'][kind + '_codecs']
            if not names:
                continue
            port = cfg['media']['rtp_port'] + offset
            lines += [f'm={kind} {port} RTP/AVP ' + ' '.join(str(table[n][0]) for n in names),
                      f'a=rtcp:{port + 1}', 'a=sendrecv']
            for n in names:
                lines += codec_lines(n, table[n][0])
            if kind == 'audio':
                lines += ['a=ptime:20']
    else:
        # Each rejected m-line stays in its original position.
        streams, choices = selected
        for s, choice in zip(streams, choices):
            if choice is None:
                lines += [f'm={s.kind} 0 {s.proto} ' + ' '.join(map(str, s.pts or [0]))]
                continue
            _, pt, name = choice
            port = cfg['media']['rtp_port'] + (2 if s.kind == 'video' else 0)
            direction = {'sendonly': 'recvonly', 'recvonly': 'sendonly'}.get(s.direction, s.direction)
            lines += [f'm={s.kind} {port} RTP/AVP {pt}', f'a=rtcp:{port + 1}', f'a={direction}']
            fmtp = s.fmtp.get(pt, '')
            if name == 'H264' and 'packetization-mode' not in params(fmtp):
                fmtp += ';packetization-mode=0'
            lines += codec_lines(name, pt, fmtp)
            if s.kind == 'audio':
                lines += ['a=ptime:20']
    return '\r\n'.join(lines) + '\r\n'
