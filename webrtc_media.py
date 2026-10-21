"""ICE + DTLS-SRTP media for SIP-over-WSS using the existing GStreamer runtime."""
import asyncio
import re
import gi
gi.require_version('Gst', '1.0')
gi.require_version('GstWebRTC', '1.0')
gi.require_version('GstSdp', '1.0')
from gi.repository import Gst, GstWebRTC, GstSdp
import sdp

Gst.init(None)
ALLOWED = {'audio': ('PCMU', 'PCMA'), 'video': ('VP8', 'H264')}


def available():
    return [name for name in ('webrtcbin', 'nicesrc', 'nicesink', 'dtlssrtpenc', 'dtlssrtpdec')
            if not Gst.ElementFactory.find(name)]


def selections(text, cfg):
    streams = sdp.parse(text)
    if not streams or len(streams) > 2 or streams[0].kind != 'audio':
        raise ValueError('WebRTC requires audio first and optional video second')
    selected = []
    for index, stream in enumerate(streams):
        if stream.kind not in ALLOWED or (index == 1 and stream.kind != 'video'):
            raise ValueError('Unsupported WebRTC media section')
        if not stream.port:
            selected.append(None)
            continue
        if stream.proto not in ('UDP/TLS/RTP/SAVPF', 'RTP/SAVPF'):
            raise ValueError('WebRTC requires DTLS-SRTP')
        preferred = cfg['webrtc'][stream.kind + '_codec']
        names = [preferred] + [c for c in ALLOWED[stream.kind] if c != preferred]
        choice = next(((stream, pt, name) for name in names for pt in stream.pts
                       if stream.codecs.get(pt) == name and name in cfg['media'][stream.kind + '_codecs']
                       and sdp.compatible(name, stream.fmtp.get(pt, ''))), None)
        if not choice:
            raise ValueError(f'No supported WebRTC {stream.kind} codec')
        selected.append(choice)
    if not selected[0]:
        raise ValueError('WebRTC audio was rejected')
    if not all(marker in text for marker in ('a=fingerprint:sha-256 ', 'a=ice-ufrag:', 'a=ice-pwd:', 'a=rtcp-mux')):
        raise ValueError('WebRTC SDP must include fingerprint, ICE credentials and RTCP mux')
    return selected


class WebRTCMedia:
    def __init__(self, cfg, log=print):
        self.cfg, self.log = cfg, log
        self.loop = asyncio.get_running_loop()
        self.pipeline = self.rtc = None
        self.error = None
        self.closed = False
        self.selected = []
        self.counters = {}
        self.receivers = []
        self.started = self.loop.time()
        self.negotiated = None

    def _count(self, key):
        def cb(*args):
            self.counters[key] = self.counters.get(key, 0) + 1
        return cb

    def _build(self, selected):
        if self.pipeline:
            raise RuntimeError('WebRTC pipeline already exists')
        self.selected = selected
        m = self.cfg['media']
        parts = [f'webrtcbin name=rtc bundle-policy=none latency={m["jitter_ms"]}']
        for index, item in enumerate(selected):
            if item is None:
                raise ValueError('Rejected media in an incoming WebRTC offer is unsupported')
            stream, pt, codec = item
            if stream.direction != 'sendrecv':
                raise ValueError('This WebRTC implementation requires sendrecv media')
            if stream.kind == 'audio':
                source = 'audiotestsrc is-live=true wave=sine samplesperbuffer=160' if m['test'] else m['audio_source']
                encoder = 'mulawenc ! rtppcmupay' if codec == 'PCMU' else 'alawenc ! rtppcmapay'
                chain = (f'{source} ! audioconvert ! audioresample ! audio/x-raw,format=S16LE,rate=8000,channels=1 '
                         f'! volume name=microphone ! {encoder} pt={pt} min-ptime=20000000 max-ptime=20000000')
                clock = 8000
            else:
                source = 'videotestsrc is-live=true pattern=ball' if m['test'] else m['video_source']
                chain = (f'{source} ! videoconvert ! videoscale ! videorate ! video/x-raw,format=I420,'
                         f'width={m["width"]},height={m["height"]},framerate={m["fps"]}/1')
                if codec == 'VP8':
                    chain += (f' ! vp8enc deadline=1 cpu-used=8 target-bitrate={m["video_bitrate"]} '
                              f'keyframe-max-dist={m["fps"] * 2} ! rtpvp8pay pt={pt} mtu=1200 picture-id-mode=15-bit')
                else:
                    chain += (f' ! openh264enc bitrate={m["video_bitrate"]} rate-control=bitrate complexity=low '
                              f'gop-size={m["fps"] * 2} ! video/x-h264,profile=constrained-baseline '
                              f'! rtph264pay pt={pt} mtu=1200 config-interval=-1 aggregate-mode=none')
                clock = 90000
            caps = f'application/x-rtp,media={stream.kind},encoding-name={codec},payload={pt},clock-rate={clock}'
            parts += [chain + f' ! {caps} ! identity name=sent{index} ! queue ! rtc.sink_{index}']
            self.counters[f'{stream.kind}/{codec}/sent_rtp'] = 0
            self.counters[f'{stream.kind}/{codec}/decoded_buffers'] = 0
        self.pipeline = Gst.parse_launch(' '.join(parts))
        self.rtc = self.pipeline.get_by_name('rtc')
        w = self.cfg['webrtc']
        self.ice = ice = self.rtc.get_property('ice-agent')
        ice.set_property('min-rtp-port', w['ice_min_port'])
        ice.set_property('max-rtp-port', w['ice_max_port'])
        for setting in ('stun-server', 'turn-server'):
            value = w.get(setting.replace('-', '_'), '')
            if value:
                self.rtc.set_property(setting, value)
        self.rtc.connect('pad-added', self._received_pad)
        for index, (stream, pt, codec) in enumerate(selected):
            self.pipeline.get_by_name(f'sent{index}').connect('handoff', self._count(f'{stream.kind}/{codec}/sent_rtp'))
        if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            self.poll()
            raise RuntimeError('Cannot start WebRTC media devices')

    def _received_pad(self, obj, pad):
        if pad.get_direction() != Gst.PadDirection.SRC or self.closed:
            return
        try:
            caps = pad.get_current_caps()
            if not caps or caps.is_empty():
                raise ValueError('Missing WebRTC receive caps')
            structure = caps.get_structure(0)
            # gst-python 1.26 returns a context manager; older releases return Structure.
            if hasattr(structure, '__enter__'):
                with structure as fields:
                    codec = fields.get_value('encoding-name').upper()
                    kind = fields.get_value('media')
            else:
                codec = structure.get_value('encoding-name').upper()
                kind = structure.get_value('media')
            if not any(s and s[0].kind == kind and s[2] == codec for s in self.selected):
                raise ValueError('Unexpected WebRTC receive codec')
            m = self.cfg['media']
            if kind == 'audio':
                chain = 'rtppcmudepay ! mulawdec' if codec == 'PCMU' else 'rtppcmadepay ! alawdec'
                chain += ' ! audioconvert ! audioresample'
                sink = 'fakesink sync=false async=false' if m['test'] else m['audio_sink']
            else:
                chain = 'rtpvp8depay ! vp8dec' if codec == 'VP8' else 'rtph264depay ! h264parse ! openh264dec'
                chain += ' ! videoconvert'
                sink = 'fakesink sync=false async=false' if m['test'] else m['video_sink']
            receiver = Gst.parse_bin_from_description('queue ! ' + chain + ' ! identity name=count ! ' + sink, True)
            receiver.get_by_name('count').connect('handoff', self._count(f'{kind}/{codec}/decoded_buffers'))
            self.pipeline.add(receiver)
            self.receivers.append(receiver)
            if pad.link(receiver.get_static_pad('sink')) != Gst.PadLinkReturn.OK:
                raise RuntimeError('Cannot link WebRTC receive stream')
            receiver.sync_state_with_parent()
        except Exception as exc:
            self.error = str(exc)

    async def _promise(self, signal, *args):
        future = self.loop.create_future()
        def finish(result, error):
            if future.done():
                return
            if error:
                future.set_exception(RuntimeError(error))
            else:
                future.set_result(result)
        def changed(promise, *unused):
            try:
                reply = promise.get_reply()
                error = str(reply.get_value('error')) if reply and reply.has_field('error') else None
                self.loop.call_soon_threadsafe(finish, reply, error)
            except Exception as exc:
                self.loop.call_soon_threadsafe(finish, None, str(exc))
        promise = Gst.Promise.new_with_change_func(changed, None, None)
        self.rtc.emit(signal, *args, promise)
        try:
            return await asyncio.wait_for(future, 10)
        except BaseException:
            promise.interrupt()
            raise

    @staticmethod
    def description(text, kind):
        if len(text.encode()) > 128 * 1024:
            raise ValueError('WebRTC SDP too large')
        # FreeSWITCH can emit unbundled SDP without mid; webrtcbin requires it.
        # Add local identifiers only when there is no BUNDLE group to reinterpret.
        if 'a=group:BUNDLE' not in text:
            sections = re.split(r'(?m)(?=^m=)', text)
            for index in range(1, len(sections)):
                if not re.search(r'(?m)^a=mid:', sections[index]):
                    kind_name = sections[index].split()[0][2:]
                    sections[index] = sections[index].rstrip() + f'\r\na=mid:{kind_name}{index - 1}\r\n'
            text = ''.join(sections)
        # RFC 4566 defaults direction to sendrecv; Gst 1.26 needs it explicit.
        sections = re.split(r'(?m)(?=^m=)', text)
        session_direction = re.search(r'(?m)^a=(sendrecv|sendonly|recvonly|inactive)\s*$', sections[0])
        for index in range(1, len(sections)):
            if not re.search(r'(?m)^a=(sendrecv|sendonly|recvonly|inactive)\s*$', sections[index]):
                direction = session_direction[1] if session_direction else 'sendrecv'
                sections[index] = sections[index].rstrip() + f'\r\na={direction}\r\n'
        text = ''.join(sections)
        result, message = GstSdp.SDPMessage.new()
        if result != GstSdp.SDPResult.OK or GstSdp.sdp_message_parse_buffer(text.encode(), message) != GstSdp.SDPResult.OK:
            raise ValueError('Invalid WebRTC SDP')
        return GstWebRTC.WebRTCSessionDescription.new(kind, message)

    async def local_description(self, kind):
        # Wait for encoder caps (H264 SPS/profile/packetization parameters).
        async with asyncio.timeout(10):
            while any(not self.pipeline.get_by_name(f'sent{i}').get_static_pad('src').get_current_caps()
                      for i in range(len(self.selected))):
                self.poll()
                await asyncio.sleep(.02)
        result = await self._promise('create-' + kind, None)
        description = result.get_value(kind)
        await self._promise('set-local-description', description)
        async with asyncio.timeout(15):
            while self.rtc.get_property('ice-gathering-state') != GstWebRTC.WebRTCICEGatheringState.COMPLETE:
                self.poll()
                await asyncio.sleep(.05)
        return self.rtc.get_property('local-description').sdp.as_text()

    async def offer(self, video=True):
        w = self.cfg['webrtc']
        audio = w['audio_codec']
        pt = 0 if audio == 'PCMU' else 8
        selected = [(sdp.Stream('audio', 9, 'UDP/TLS/RTP/SAVPF', [pt], '0.0.0.0'), pt, audio)]
        if video and self.cfg['media']['video']:
            codec = w['video_codec']
            pt = 97 if codec == 'VP8' else 96
            selected.append((sdp.Stream('video', 9, 'UDP/TLS/RTP/SAVPF', [pt], '0.0.0.0'), pt, codec))
        self._build(selected)
        return await self.local_description('offer')

    async def answer(self, remote):
        chosen = selections(remote, self.cfg)
        self._build(chosen)
        await self._promise('set-remote-description', self.description(remote, GstWebRTC.WebRTCSDPType.OFFER))
        answer = await self.local_description('answer')
        self.negotiated = self.loop.time()
        return answer

    async def accept_answer(self, remote):
        chosen = selections(remote, self.cfg)
        if len(chosen) != len(self.selected):
            raise ValueError('WebRTC answer changed media count')
        for original, answer in zip(self.selected, chosen):
            if answer and (answer[0].kind != original[0].kind or answer[1:] != original[1:]):
                raise ValueError('WebRTC answer selected an unoffered codec')
        await self._promise('set-remote-description', self.description(remote, GstWebRTC.WebRTCSDPType.ANSWER))
        self.negotiated = self.loop.time()

    def poll(self):
        if self.error:
            raise RuntimeError('WebRTC: ' + self.error)
        if not self.pipeline:
            return
        bus = self.pipeline.get_bus()
        while True:
            msg = bus.pop_filtered(Gst.MessageType.ERROR | Gst.MessageType.EOS)
            if not msg:
                break
            if msg.type == Gst.MessageType.ERROR:
                error, debug = msg.parse_error()
                self.error = f'{error.message} ({debug})'
            else:
                self.error = 'media source ended'
        if self.rtc.get_property('connection-state') == GstWebRTC.WebRTCPeerConnectionState.FAILED:
            self.error = 'ICE/DTLS connection failed'
        if self.negotiated and self.loop.time() - self.negotiated > 30 and self.rtc.get_property('connection-state') != GstWebRTC.WebRTCPeerConnectionState.CONNECTED:
            self.error = 'ICE/DTLS connection timeout'
        if self.error:
            raise RuntimeError('WebRTC: ' + self.error)

    def mute(self, value):
        volume = self.pipeline.get_by_name('microphone') if self.pipeline else None
        if volume:
            volume.set_property('mute', value)

    def stats(self):
        result = dict(self.counters)
        if self.rtc:
            result['connection'] = self.rtc.get_property('connection-state').value_nick
            result['ice'] = self.rtc.get_property('ice-connection-state').value_nick
        return {'webrtc': result}

    def close(self):
        self.closed = True
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline.get_state(2 * Gst.SECOND)



