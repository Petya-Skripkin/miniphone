"""Configuration, deliberately limited to the requested codecs."""
import socket
import tomllib
from pathlib import Path

AUDIO = {"PCMU": (0, 8000), "PCMA": (8, 8000), "G722": (9, 8000), "G729": (18, 8000)}
VIDEO = {"H264": (96, 90000), "VP8": (97, 90000), "AV1": (98, 90000)}


def load(path):
    cfg = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    s, m = cfg["sip"], cfg["media"]
    for key in ("server", "username", "password"):
        if not s.get(key) or any(c in s[key] for c in "\r\n"):
            raise ValueError(f"Invalid sip.{key}")
    if any(c in s['server'] for c in '/@;: '):
        raise ValueError("sip.server must be an IPv4 address or DNS hostname; use sip.port separately")
    s.setdefault("port", 5060)
    s.setdefault("local_port", 5060)
    s.setdefault("bind", "0.0.0.0")
    s.setdefault("register", True)
    s.setdefault("expires", 300)
    s.setdefault('transport', 'udp')
    if s['transport'] not in ('udp', 'wss'):
        raise ValueError('sip.transport must be udp or wss')
    s.setdefault('wss_url', f'wss://{s["server"]}:7443/')
    s["domain"] = s.get("domain") or s["server"]
    s["auth_username"] = s.get("auth_username") or s["username"]
    for key in ('domain', 'auth_username', 'username'):
        if any(c in s[key] for c in '\r\n<>" '):
            raise ValueError(f"Invalid sip.{key}")
    s["server_ip"] = socket.gethostbyname(s["server"])
    if not s.get("advertise_ip"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((s["server_ip"], s["port"]))
            s["advertise_ip"] = probe.getsockname()[0]
    socket.inet_aton(s['advertise_ip'])
    for key, allowed in (("audio_codecs", AUDIO), ("video_codecs", VIDEO)):
        if not isinstance(m[key], list) or len(m[key]) != len(set(m[key])):
            raise ValueError(f"media.{key} must be a list without duplicates")
        if any(c not in allowed for c in m[key]):
            raise ValueError(f"media.{key}: allowed: {', '.join(allowed)}")
    if not m['audio_codecs']:
        raise ValueError('At least one audio codec is required')
    for port in (s['port'], s['local_port']):
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('Invalid SIP port')
    if not 1024 <= m['rtp_port'] <= 65532 or m['rtp_port'] % 2:
        raise ValueError('media.rtp_port must be an even port between 1024 and 65532')
    if not 60 <= s['expires'] <= 86400:
        raise ValueError('sip.expires must be 60..86400')
    for key, lo, hi in [('width', 160, 1280), ('height', 120, 720), ('fps', 1, 30),
                        ('video_bitrate', 64000, 10000000), ('jitter_ms', 0, 2000)]:
        if not lo <= m[key] <= hi:
            raise ValueError(f'media.{key} must be {lo}..{hi}')
    if m['width'] % 2 or m['height'] % 2:
        raise ValueError('Video width and height must be even (I420)')
    w = cfg.setdefault('webrtc', {})
    for key, value in dict(audio_codec='PCMU', video_codec='VP8', stun_server='', turn_server='',
                           ice_min_port=41000, ice_max_port=41100).items():
        w.setdefault(key, value)
    if s['transport'] == 'wss' and (w['audio_codec'] not in ('PCMU', 'PCMA') or w['audio_codec'] not in m['audio_codecs']):
        raise ValueError('webrtc.audio_codec must be enabled PCMU or PCMA')
    if s['transport'] == 'wss' and m['video'] and (w['video_codec'] not in ('VP8', 'H264') or w['video_codec'] not in m['video_codecs']):
        raise ValueError('webrtc.video_codec must be enabled VP8 or H264')
    if not 1024 <= w['ice_min_port'] <= w['ice_max_port'] <= 65535:
        raise ValueError('Invalid WebRTC ICE UDP port range')
    return cfg
