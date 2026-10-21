#!/usr/bin/env python3
"""MiniPhone: one-account, one-call console SIP audio/video phone."""
import argparse
import asyncio
import contextlib
import copy
import json
import os
import re
import shlex
import signal
import sys
import time
from pathlib import Path
from settings import load
from sip import Endpoint, Message, destination, uri, tag, token
import sdp


def log(text):
    print(time.strftime('%H:%M:%S'), text, flush=True)


def routes(headers):
    return [r.strip() for h in headers for r in re.split(r',(?=\s*<)', h)]


class Phone:
    def __init__(self, cfg, logger=log, media_factory=None):
        self.cfg, self.log = cfg, logger
        self.sip = Endpoint(cfg['sip'], logger)
        self.sip.handler = self.incoming
        self.sip.on_disconnect = self.disconnected
        self.reg_wakeup = asyncio.Event()
        self.call = None
        self.registered = False
        self.reg_id = token() + '@' + cfg['sip']['advertise_ip']
        self.reg_from = f'<sip:{cfg["sip"]["username"]}@{cfg["sip"]["domain"]}>;tag={token()}'
        self.reg_seq = 0
        self.reg_lock = asyncio.Lock()
        self.done = asyncio.Event()
        self.tasks = set()
        self.finals = {}
        if media_factory is None:
            from media import Media
            media_factory = Media
        self.media_factory = media_factory

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        def finished(t):
            if not t.cancelled() and t.exception():
                self.log(f'Error: {t.exception()}')
        task.add_done_callback(finished)
        return task

    async def start(self):
        await self.sip.start()
        self.spawn(self.monitor())
        if self.cfg['sip']['register']:
            self.spawn(self.registration_loop())

    async def register(self, expires=None):
        async with self.reg_lock:
            s = self.cfg['sip']
            expires = s['expires'] if expires is None else expires
            self.reg_seq += 1
            req = self.sip.request('REGISTER', 'sip:' + s['domain'], call_id=self.reg_id,
                seq=self.reg_seq, from_value=self.reg_from,
                to_value=f'<sip:{s["username"]}@{s["domain"]}>', extra=[('Expires', str(expires))])
            def track(r):
                self.reg_seq = int(r.get('CSeq').split()[0])
            res, sent = await self.sip.authenticated(req, (s['server_ip'], s['port']), on_request=track)
            if res.status == 423 and expires:
                minimum = int(res.get('Min-Expires', '300'))
                if 60 <= minimum <= 86400:
                    s['expires'] = minimum
                raise ValueError(f'Registration interval too short; retry with {s["expires"]} seconds')
            if res.status != 200:
                self.registered = False
                raise ValueError('Registration failed: ' + res.first)
            self.registered = bool(expires)
            granted = int(res.get('Expires', str(expires)))
            for contact in res.all('Contact'):
                if uri(sent.get('Contact')) in contact:
                    m = re.search(r';expires=(\d+)', contact)
                    if m:
                        granted = int(m[1])
            self.log('Registered: ' + s['username'] + '@' + s['domain'] if expires else 'Unregistered')
            return max(1, granted)

    def disconnected(self):
        self.registered = False
        self.cleanup()
        self.reg_wakeup.set()

    async def registration_loop(self):
        while not self.done.is_set():
            self.reg_wakeup.clear()
            try:
                granted = await self.register()
                delay = max(1, granted * .8)
            except (OSError, ValueError, TimeoutError, KeyError) as exc:
                self.registered = False
                self.log(f'Registration: {exc}; retry in 30 s')
                delay = 30
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.reg_wakeup.wait(), delay)

    def cleanup(self, call=None):
        call = call or self.call
        if call and call.get('media'):
            self.log('Media counters: ' + json.dumps(call['media'].stats()))
            call['media'].close()
            call['media'] = None
        if self.call is call:
            self.call = None

    def final(self, req, addr, code, reason, local_tag, body=''):
        res = self.sip.respond(req, addr, code, reason, local_tag, body)
        key = (req.get('Call-ID'), req.get('CSeq').split()[0], tag(req.get('From')), tag(res.get('To')))
        event = asyncio.Event()
        self.finals[key] = event
        async def resend():
            deadline, interval = time.monotonic() + 32, .5
            try:
                while time.monotonic() < deadline:
                    try:
                        await asyncio.wait_for(event.wait(), min(interval, deadline - time.monotonic()))
                        return
                    except asyncio.TimeoutError:
                        self.sip.send(res, addr)
                        interval = min(4, interval * 2)
                if code == 200 and self.call and self.call['id'] == req.get('Call-ID'):
                    self.log('No ACK: ending unanswered session')
                    self.cleanup()
            finally:
                self.finals.pop(key, None)
        self.spawn(resend())
        return res

    def matches_dialog(self, req):
        c = self.call
        return bool(c and c['id'] == req.get('Call-ID') and tag(req.get('To')) == tag(c['local'])
                    and tag(req.get('From')) == tag(c['remote']))

    async def incoming(self, req, addr):
        method = req.method
        if method == 'ACK':
            key = (req.get('Call-ID'), req.get('CSeq').split()[0], tag(req.get('From')), tag(req.get('To')))
            if key in self.finals:
                self.finals[key].set()
            if self.matches_dialog(req) and self.call['state'] == 'answering':
                self.call['state'] = 'active'
                self.log('Call connected')
            return
        if method == 'OPTIONS':
            self.sip.respond(req, addr, 200, 'OK', extra=[('Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS')])
            return
        if method == 'CANCEL':
            c = self.call
            matches = (c and c['incoming'] and c['id'] == req.get('Call-ID')
                       and req.key[0] == c['req'].key[0]
                       and req.get('CSeq').split()[0] == c['req'].get('CSeq').split()[0])
            self.sip.respond(req, addr, 200 if matches else 481, 'OK' if matches else 'Call/Transaction Does Not Exist')
            if matches and c['state'] in ('ringing', 'preparing-answer'):
                self.final(c['req'], c['addr'], 487, 'Request Terminated', tag(c['local']))
                self.cleanup(c)
                self.log('Caller cancelled')
            return
        if method == 'BYE':
            if not self.matches_dialog(req):
                self.sip.respond(req, addr, 481, 'Call/Transaction Does Not Exist')
            else:
                self.sip.respond(req, addr, 200, 'OK', tag(self.call['local']))
                self.cleanup()
                self.log('Remote hangup')
            return
        if method != 'INVITE':
            self.sip.respond(req, addr, 405, 'Method Not Allowed', extra=[('Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS')])
            return
        if req.get('Require'):
            self.sip.respond(req, addr, 420, 'Bad Extension', extra=[('Unsupported', req.get('Require'))])
            return
        if tag(req.get('To')):
            code = 488 if self.matches_dialog(req) else 481
            self.sip.respond(req, addr, code, 'Not Acceptable Here' if code == 488 else 'Call/Transaction Does Not Exist')
            return
        if self.call:
            self.sip.respond(req, addr, 486, 'Busy Here')
            return
        self.sip.respond(req, addr, 100, 'Trying')
        try:
            if req.get('Content-Type').split(';')[0].lower() != 'application/sdp' or not req.body:
                raise ValueError('INVITE must contain an SDP offer')
            streams = sdp.parse(req.body)
            if self.sip.reliable:
                from webrtc_media import selections
                selected = selections(req.body, self.cfg)
            else:
                selected = sdp.choose(streams, self.cfg)
            remote_target = uri(req.get('Contact'))
            if self.sip.reliable:
                if not remote_target.startswith('sip:'):
                    raise ValueError('Invalid SIP Contact')
            else:
                destination(remote_target)
        except (ValueError, KeyError, IndexError, OSError) as exc:
            self.sip.respond(req, addr, 488, 'Not Acceptable Here')
            self.log(f'Rejected offer: {exc}')
            return
        local_tag = token()
        self.call = dict(id=req.get('Call-ID'), incoming=True, state='ringing', req=req, addr=addr,
                         local=req.get('To') + ';tag=' + local_tag, remote=req.get('From'),
                         target=remote_target, routes=routes(req.all('Record-Route')), seq=1,
                         selected=selected, streams=streams, media=None, cancelled=False)
        self.sip.respond(req, addr, 180, 'Ringing', local_tag)
        self.log('\aIncoming: ' + req.get('From') + ' вЂ” answer / reject')
        if self.cfg['media']['auto_answer']:
            await self.answer()

    def dialog_request(self, c, method, seq=None):
        target, route_headers = c['target'], list(c['routes'])
        if route_headers:
            next_hop = c['addr'] if self.sip.reliable else destination(route_headers[0])
            if not re.search(r';lr(?:[;>]|$)', route_headers[0], re.I):
                target = uri(route_headers.pop(0))
                route_headers.append('<' + c['target'] + '>')
        else:
            next_hop = c['addr'] if self.sip.reliable else destination(target)
        req = self.sip.request(method, target, c['id'], seq=seq if seq is not None else c['seq'],
                               from_value=c['local'], to_value=c['remote'],
                               extra=[('Route', r) for r in route_headers])
        return req, next_hop

    async def answer(self):
        c = self.call
        if not c or c['state'] != 'ringing':
            raise ValueError('No incoming call to answer')
        c['state'] = 'preparing-answer'
        try:
            if self.sip.reliable:
                from webrtc_media import WebRTCMedia
                c['media'] = WebRTCMedia(self.cfg, self.log)
                body = await c['media'].answer(c['req'].body)
            else:
                c['media'] = self.media_factory(self.cfg, c['selected'], self.log)
                body = sdp.make(self.cfg, (c['streams'], c['selected']))
            if self.call is not c:
                return
            c['media'].poll()
        except Exception as exc:
            if self.call is not c:
                return
            self.final(c['req'], c['addr'], 500, 'Media Device Error', tag(c['local']))
            self.cleanup(c)
            raise RuntimeError(f'Cannot open media devices: {exc}') from exc
        c['state'] = 'answering'
        self.final(c['req'], c['addr'], 200, 'OK', tag(c['local']), body)
        self.log('Answered; waiting for ACK')

    async def reject(self):
        c = self.call
        if not c or c['state'] != 'ringing':
            raise ValueError('No ringing call')
        self.final(c['req'], c['addr'], 486, 'Busy Here', tag(c['local']))
        self.cleanup(c)

    async def dial(self, number, video=True):
        if self.call:
            raise ValueError('A call is already in progress')
        if not number or any(x in number for x in '\r\n <>"'):
            raise ValueError('Invalid number / SIP URI')
        s = self.cfg['sip']
        if number.startswith('sip:'):
            target, addr = number, ((s['server_ip'], s['port']) if self.sip.reliable else destination(number))
        else:
            target, addr = 'sip:' + number + '@' + s['domain'], (s['server_ip'], s['port'])
        offer = '' if self.sip.reliable else sdp.make(self.cfg, video=video)
        req = self.sip.request('INVITE', target, body=offer)
        c = dict(id=req.get('Call-ID'), incoming=False, state='preparing' if self.sip.reliable else 'dialing', req=req, addr=addr,
                 local=req.get('From'), remote=req.get('To'), seq=1, cancelled=False,
                 provisional=False, cancel_sent=False, media=None, offer=sdp.parse(offer))
        self.call = c
        self.log('Calling ' + target + (' (audio/video)' if video and self.cfg['media']['video'] else ' (audio)'))
        def progress(res):
            c['provisional'] = True
            self.log(res.first)
            if c['cancelled'] and not c['cancel_sent']:
                self.spawn(self.cancel(c))
        def track(sent):
            c['req'] = sent
            c['seq'] = int(sent.get('CSeq').split()[0])
            c['provisional'] = False
        try:
            if self.sip.reliable:
                from webrtc_media import WebRTCMedia
                c['media'] = WebRTCMedia(self.cfg, self.log)
                req.body = await c['media'].offer(video)
                if self.call is not c or c['cancelled']:
                    self.cleanup(c)
                    return
                req.set('Content-Type', 'application/sdp')
                c['state'] = 'dialing'
            res, sent = await self.sip.authenticated(req, addr, progress, track)
            if res.status >= 300:
                self.log('Call ended: ' + res.first)
                self.cleanup(c)
                return
            c['remote'] = res.get('To')
            c['target'] = uri(res.get('Contact')) or target
            c['routes'] = list(reversed(routes(res.all('Record-Route'))))
            c['state'] = 'active'
            ack, ack_addr = self.dialog_request(c, 'ACK', c['seq'])
            self.sip.remember_ack(res, ack, ack_addr)
            if c['cancelled']:
                await self.hangup()
                return
            try:
                if res.get('Content-Type').split(';')[0].lower() != 'application/sdp':
                    raise ValueError('Answer has no SDP')
                if self.sip.reliable:
                    await c['media'].accept_answer(res.body)
                    selected = c['media'].selected
                else:
                    streams = sdp.parse(res.body)
                    sdp.validate_answer(streams, c['offer'])
                    selected = sdp.choose(streams, self.cfg)
                    c['media'] = self.media_factory(self.cfg, selected, self.log)
                c['media'].poll()
                self.log('Call connected: ' + ', '.join(x[2] for x in selected if x))
            except Exception:
                await self.hangup()
                raise
        except (OSError, ValueError, TimeoutError, RuntimeError, KeyError, IndexError) as exc:
            self.log(f'Call failed: {exc}')
            self.cleanup(c)

    async def cancel(self, c):
        if c['cancel_sent'] or not c['provisional'] or c['state'] != 'dialing':
            return
        c['cancel_sent'] = True
        sent = c['req']
        req = Message(sent.first.replace('INVITE ', 'CANCEL ', 1),
                      [(k, v) for k, v in sent.headers if k.lower() in ('via', 'from', 'to', 'call-id', 'max-forwards', 'route')])
        req.set('CSeq', str(c['seq']) + ' CANCEL')
        res = await self.sip.transact(req, c['addr'])
        self.log('CANCEL: ' + res.first)

    async def hangup(self):
        c = self.call
        if not c:
            return
        if c['state'] == 'preparing':
            c['cancelled'] = True
            self.cleanup(c)
        elif c['state'] == 'preparing-answer':
            self.final(c['req'], c['addr'], 480, 'Temporarily Unavailable', tag(c['local']))
            self.cleanup(c)
        elif c['state'] == 'ringing':
            await self.reject()
        elif c['state'] == 'dialing':
            c['cancelled'] = True
            await self.cancel(c)
            self.log('Cancelling outgoing call')
        elif c['state'] in ('active', 'answering'):
            c['state'] = 'ending'
            if c.get('media'):
                self.log('Media counters: ' + json.dumps(c['media'].stats()))
                c['media'].close()
                c['media'] = None
            c['seq'] += 1
            req, addr = self.dialog_request(c, 'BYE')
            try:
                res, _ = await self.sip.authenticated(req, addr)
                self.log('Hangup: ' + res.first)
            finally:
                self.cleanup(c)

    async def monitor(self):
        while not self.done.is_set():
            c = self.call
            if c and c.get('media'):
                try:
                    c['media'].poll()
                except RuntimeError as exc:
                    self.log('Media failed: ' + str(exc))
                    self.spawn(self.hangup())
            await asyncio.sleep(.1)

    def status(self):
        c = self.call
        return {'registered': self.registered, 'call': c['state'] if c else 'idle',
                'transport': 'wss' if self.sip.reliable else 'udp',
                'test_media': self.cfg['media']['test'],
                'media': c['media'].stats() if c and c.get('media') else {}}

    async def command(self, line):
        parts = shlex.split(line)
        if not parts:
            return
        cmd, *args = parts
        if cmd == 'call':
            if not args or len(args) > 2 or (len(args) == 2 and args[1] not in ('audio', 'video')):
                raise ValueError('Usage: call NUMBER [audio|video]')
            self.spawn(self.dial(args[0], len(args) == 1 or args[1] == 'video'))
        elif cmd == 'answer':
            await self.answer()
        elif cmd == 'reject':
            await self.reject()
        elif cmd == 'hangup':
            self.spawn(self.hangup())
        elif cmd in ('mute', 'unmute'):
            if self.call and self.call.get('media'):
                self.call['media'].mute(cmd == 'mute')
        elif cmd == 'status':
            self.log(json.dumps(self.status(), ensure_ascii=False))
        elif cmd == 'register':
            self.spawn(self.register())
        elif cmd == 'codecs':
            if self.sip.reliable:
                self.log('WebRTC: audio PCMU/PCMA; video VP8/H264; offer: ' + self.cfg['webrtc']['audio_codec'] + '/' + self.cfg['webrtc']['video_codec'])
                return
            self.log('Audio: ' + ', '.join(self.cfg['media']['audio_codecs']) + '; video: ' + ', '.join(self.cfg['media']['video_codecs']))
        elif cmd in ('quit', 'exit'):
            self.done.set()
        elif cmd in ('help', '?'):
            self.log('call NUMBER [audio|video] | answer | reject | hangup | mute | unmute | status | codecs | register | quit')
        else:
            raise ValueError('Unknown command; type help')

    async def console(self):
        # A daemon reader keeps SIGINT shutdown independent of a blocked input().
        import threading
        loop = asyncio.get_running_loop()
        queue = asyncio.Queue()
        def reader():
            for line in sys.stdin:
                if loop.is_closed():
                    return
                loop.call_soon_threadsafe(queue.put_nowait, line)
            if not loop.is_closed():
                loop.call_soon_threadsafe(queue.put_nowait, None)
        threading.Thread(target=reader, daemon=True).start()
        await self.command('help')
        while not self.done.is_set():
            line = await queue.get()
            if line is None:
                self.done.set()
                return
            try:
                await self.command(line)
            except (ValueError, RuntimeError, OSError) as exc:
                self.log(str(exc))

    async def close(self):
        self.done.set()
        # Stop registration renewals before unregistering.
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.hangup(), 4)
        self.cleanup()
        if self.registered:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.register(0), 4)
        await self.sip.close()


def environment_warnings(cfg):
    m = cfg['media']
    if m['test'] or not m['video']:
        return []
    warnings = []
    if sys.platform.startswith('linux'):
        if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')) and any(
                sink in m['video_sink'] for sink in ('autovideosink', 'ximagesink', 'xvimagesink', 'glimagesink', 'waylandsink')):
            warnings.append('No graphical display in this session. For video, run ./run.sh from a terminal '
                            'inside the Debian desktop; an ordinary SSH session cannot show the video window. '
                            'Audio-only calls are available with: call NUMBER audio')
        match = re.search(r'device=(/dev/video\d+)', m['video_source'])
        if match and not os.access(match[1], os.R_OK | os.W_OK):
            warnings.append(f'Camera {match[1]} is missing or inaccessible. After adding the video group, '
                            'log out and log in again, then restart this program.')
    return warnings


async def run(args):
    if args.devices:
        from media import devices
        print(json.dumps(devices(), ensure_ascii=False, indent=2))
        return 0
    cfg = load(args.config)
    if args.test:
        cfg['media']['test'] = True
    if args.no_register:
        cfg['sip']['register'] = False
    if args.auto_answer:
        cfg['media']['auto_answer'] = True
    from media import available
    capabilities = available()
    configured = cfg['media']['audio_codecs'] + (cfg['media']['video_codecs'] if cfg['media']['video'] else [])
    missing = {n: capabilities[n] for n in configured if capabilities[n]}
    if cfg['sip']['transport'] == 'wss':
        configured = [cfg['webrtc']['audio_codec']] + ([cfg['webrtc']['video_codec']] if cfg['media']['video'] else [])
        missing = {n: capabilities[n] for n in configured if capabilities[n]}
        from webrtc_media import available as webrtc_available
        if webrtc_available():
            missing['WebRTC'] = webrtc_available()
    if args.check:
        print(json.dumps({'server': cfg['sip']['server'], 'server_ip': cfg['sip']['server_ip'],
                          'local_ip': cfg['sip']['advertise_ip'], 'transport': cfg['sip']['transport'], 'codecs': capabilities,
                          'missing_configured': missing}, indent=2))
        return 1 if missing else 0
    if missing:
        raise RuntimeError('Missing configured codecs (install packages or explicitly edit config): ' + str(missing))
    for warning in environment_warnings(cfg):
        log('WARNING: ' + warning)
    phone = Phone(cfg)
    if args.register_check:
        await phone.sip.start()
        try:
            await phone.register()
            return 0
        finally:
            await phone.close()
    await phone.start()
    if phone.sip.reliable:
        log('MiniPhone WSS: ' + cfg['sip']['wss_url'])
    else:
        log(f'MiniPhone listening on {cfg["sip"]["advertise_ip"]}:{cfg["sip"]["local_port"]}')
    if cfg['media']['test']:
        log('TEST MEDIA: tone + test picture; real devices are not used')
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            asyncio.get_running_loop().add_signal_handler(sig, phone.done.set)
    console = asyncio.create_task(phone.console())
    try:
        await phone.done.wait()
    finally:
        console.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await console
        await phone.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=str(Path(__file__).with_name('config.toml')))
    parser.add_argument('--test', action='store_true', help='test tone/picture and discard received output')
    parser.add_argument('--check', action='store_true', help='check configuration and codec availability')
    parser.add_argument('--devices', action='store_true', help='list local audio/video devices')
    parser.add_argument('--register-check', action='store_true', help='register, report result, unregister and exit')
    parser.add_argument('--no-register', action='store_true', help='direct SIP calls without registration')
    parser.add_argument('--auto-answer', action='store_true', help='explicitly enable automatic answer')
    args = parser.parse_args()
    try:
        return asyncio.run(run(args))
    except (OSError, ValueError, RuntimeError, TimeoutError, KeyError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
