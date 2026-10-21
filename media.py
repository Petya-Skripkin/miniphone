"""Explicit GStreamer media chains: no decodebin, codec discovery or SIP SDK.

GStreamer handles device I/O, codecs, jitter buffering, RTP/RTCP. Our two small
bridges provide G.729 encoding and AV1 RTP where Debian has no stock element.
"""
import ctypes as C
import ctypes.util
import socket
import time
import gi
gi.require_version('Gst', '1.0')
gi.require_version('Gio', '2.0')
from gi.repository import Gst, Gio
from av1rtp import Payloader, Depayloader
from sdp import params

Gst.init(None)

AUDIO_CHAINS = {
    'PCMU': ('mulawenc', 'rtppcmupay', 'rtppcmudepay', 'mulawdec', 8000),
    'PCMA': ('alawenc', 'rtppcmapay', 'rtppcmadepay', 'alawdec', 8000),
    'G722': ('avenc_g722', 'rtpg722pay', 'rtpg722depay', 'avdec_g722', 16000),
    'G729': ('', 'rtpg729pay', 'rtpg729depay', 'avdec_g729', 8000),
}
VIDEO_CHAINS = {
    'H264': ('openh264enc', 'rtph264pay', 'rtph264depay', 'openh264dec'),
    'VP8': ('vp8enc', 'rtpvp8pay', 'rtpvp8depay', 'vp8dec'),
    'AV1': ('av1enc', '', '', 'av1dec'),
}


def available():
    result = {}
    for name, chain in (AUDIO_CHAINS | VIDEO_CHAINS).items():
        missing = [n for n in chain if isinstance(n, str) and n and not Gst.ElementFactory.find(n)]
        if name == 'G729' and not ctypes.util.find_library('bcg729'):
            missing.append('libbcg729')
        result[name] = missing
    return result


def devices():
    monitor = Gst.DeviceMonitor.new()
    for kind in ('Audio/Source', 'Audio/Sink', 'Video/Source'):
        monitor.add_filter(kind, None)
    monitor.start()
    try:
        return [{'name': d.get_display_name(), 'class': d.get_device_class(),
                 'properties': d.get_properties().to_string() if d.get_properties() else ''}
                for d in monitor.get_devices()]
    finally:
        monitor.stop()


def raw_buffer(data, pts=None, duration=None):
    buf = Gst.Buffer.new_allocate(None, len(data), None)
    buf.fill(0, data)
    if pts is not None:
        buf.pts = pts
    if duration is not None:
        buf.duration = duration
    return buf


def sample_bytes(sink):
    sample = sink.emit('pull-sample')
    if sample is None:
        return None, None
    buf = sample.get_buffer()
    return buf.extract_dup(0, buf.get_size()), buf


class G729Encoder:
    def __init__(self, source):
        self.source = source
        self.lib = C.CDLL(ctypes.util.find_library('bcg729'))
        self.lib.initBcg729EncoderChannel.argtypes = [C.c_uint8]
        self.lib.initBcg729EncoderChannel.restype = C.c_void_p
        self.lib.bcg729Encoder.argtypes = [C.c_void_p, C.POINTER(C.c_int16), C.POINTER(C.c_uint8), C.POINTER(C.c_uint8)]
        self.lib.closeBcg729EncoderChannel.argtypes = [C.c_void_p]
        self.ctx = self.lib.initBcg729EncoderChannel(0) # continuous speech, annexb=no
        if not self.ctx:
            raise MemoryError('G729 encoder allocation failed')
        self.pending, self.pts = bytearray(), None

    def push(self, data, pts):
        if self.pts is None:
            self.pts = pts if pts != Gst.CLOCK_TIME_NONE else 0
        self.pending.extend(data)
        while len(self.pending) >= 160:
            pcm = (C.c_int16 * 80).from_buffer_copy(self.pending[:160])
            del self.pending[:160]
            encoded, length = (C.c_uint8 * 10)(), C.c_uint8()
            self.lib.bcg729Encoder(self.ctx, pcm, encoded, C.byref(length))
            self.source.emit('push-buffer', raw_buffer(bytes(encoded[:length.value]), self.pts, 10000000))
            self.pts += 10000000

    def close(self):
        if self.ctx:
            self.lib.closeBcg729EncoderChannel(self.ctx)
            self.ctx = None


class MediaStream:
    def __init__(self, cfg, selected, log=print):
        self.cfg, self.log = cfg, log
        self.stream, self.pt, self.codec = selected
        self.kind = self.stream.kind
        self.pipeline = None
        self.bridge = None
        self.sockets = []
        self.error = None
        self.stats = {'sent_rtp': 0, 'received_rtp': 0, 'decoded_buffers': 0, 'sent_rtcp': 0, 'received_rtcp': 0}
        self.depay = Depayloader()
        self.pay = Payloader(self.pt)
        try:
            self._build()
        except Exception:
            self.close()
            raise

    def _count(self, name):
        def handler(*args):
            self.stats[name] += 1
        return handler

    def _build(self):
        m, s, name, pt = self.cfg['media'], self.stream, self.codec, self.pt
        local = m['rtp_port'] + (2 if self.kind == 'video' else 0)
        clock = 8000 if self.kind == 'audio' else 90000
        caps = f'application/x-rtp,media={self.kind},encoding-name={name},clock-rate={clock},payload={pt}'
        for key, value in params(s.fmtp.get(pt, '')).items():
            # Only recognized remote fmtp values; never interpolate arbitrary SDP into a pipeline.
            if key in ('sprop-parameter-sets', 'profile-level-id', 'packetization-mode'):
                if not all(c.isalnum() or c in '+/=,-' for c in value):
                    raise ValueError('Invalid codec parameter')
                caps += f',{key}=(string)"{value}"'
        caps_obj = Gst.Caps.from_string(caps)
        send = s.direction in ('sendrecv', 'recvonly') and s.ip != '0.0.0.0'
        receive = s.direction in ('sendrecv', 'sendonly') and s.ip != '0.0.0.0'
        parts = [f'rtpbin name=rtp latency={m["jitter_ms"]} drop-on-latency=true']
        if self.kind == 'audio':
            enc, pay, depay, dec, rate = AUDIO_CHAINS[name]
            source = 'audiotestsrc is-live=true wave=sine freq=440 samplesperbuffer=160' if m['test'] else m['audio_source']
            sink = 'fakesink sync=false async=false' if m['test'] else m['audio_sink']
            raw = f'{source} ! audioconvert ! audioresample ! audio/x-raw,format=S16LE,rate={rate},channels=1 ! volume name=microphone'
            if send:
                if name == 'G729':
                    parts += [raw + ' ! appsink name=pcm emit-signals=true sync=false async=false max-buffers=8 drop=true']
                    outgoing = 'appsrc name=encoded is-live=true format=time caps="audio/G729,rate=8000,channels=1"'
                else:
                    outgoing = raw + ' ! ' + enc
                parts += [outgoing + f' ! {pay} pt={pt} min-ptime=20000000 max-ptime=20000000 ! rtp.send_rtp_sink_0']
            if receive:
                parts += [f'queue name=incoming ! {depay} ! {dec} ! audioconvert ! audioresample ! identity name=decoded ! {sink}']
        else:
            enc, pay, depay, dec = VIDEO_CHAINS[name]
            source = 'videotestsrc is-live=true pattern=ball' if m['test'] else m['video_source']
            sink = 'fakesink sync=false async=false' if m['test'] else m['video_sink']
            if send:
                raw = (f'{source} ! videoconvert ! videoscale ! videorate ! '
                       f'video/x-raw,format=I420,width={m["width"]},height={m["height"]},framerate={m["fps"]}/1')
                if name == 'H264':
                    outgoing = (raw + f' ! openh264enc bitrate={m["video_bitrate"]} rate-control=bitrate '
                                f'gop-size={m["fps"] * 2} complexity=low ! video/x-h264,profile=constrained-baseline '
                                f'! rtph264pay pt={pt} mtu=1200 config-interval=-1 aggregate-mode=none')
                elif name == 'VP8':
                    outgoing = (raw + f' ! vp8enc deadline=1 cpu-used=8 target-bitrate={m["video_bitrate"]} '
                                f'keyframe-max-dist={m["fps"] * 2} ! rtpvp8pay pt={pt} mtu=1200 picture-id-mode=15-bit')
                else:
                    parts += [raw + f' ! av1enc usage-profile=realtime cpu-used=8 threads=2 lag-in-frames=0 '
                              f'target-bitrate={m["video_bitrate"] // 1000} keyframe-max-dist={m["fps"] * 2} '
                              '! av1parse ! video/x-av1,stream-format=obu-stream,alignment=tu '
                              '! appsink name=av1out emit-signals=true sync=false async=false max-buffers=3 drop=true']
                    outgoing = f'appsrc name=av1rtp is-live=true format=time caps="{caps}"'
                parts += [outgoing + ' ! rtp.send_rtp_sink_0']
            if receive:
                if name == 'AV1':
                    parts += ['queue name=incoming ! appsink name=av1in emit-signals=true sync=false async=false max-buffers=100 drop=true']
                    incoming = 'appsrc name=av1decoded is-live=true format=time do-timestamp=true caps="video/x-av1,stream-format=obu-stream,alignment=tu" ! av1parse'
                else:
                    incoming = f'queue name=incoming ! {depay}'
                    if name == 'H264':
                        incoming += ' ! h264parse'
                parts += [incoming + f' ! {dec} ! videoconvert ! identity name=decoded ! {sink}']
        if send:
            parts += [f'rtp.send_rtp_src_0 ! identity name=sent ! udpsink name=rtpout host={s.ip} port={s.port} sync=false async=false']
        if receive:
            # Caps set via API to avoid quoting remote SDP into the pipeline grammar.
            parts += [f'udpsrc name=rtpin address={self.cfg["sip"]["bind"]} port={local} ! identity name=received ! rtp.recv_rtp_sink_0']
        if send or receive:
            parts += [f'rtp.send_rtcp_src_0 ! identity name=rtcpsent ! udpsink name=rtcpout host={s.ip} port={s.rtcp} sync=false async=false',
                      f'udpsrc name=rtcpin port={local + 1} address={self.cfg["sip"]["bind"]} caps="application/x-rtcp" ! identity name=rtcpreceived ! rtp.recv_rtcp_sink_0']
        self.pipeline = Gst.parse_launch(' '.join(parts))
        # Send from the advertised receive port. PBXs use symmetric RTP and
        # otherwise redirect return media to udpsink's random ephemeral port.
        for port, names in [(local, ('rtpin', 'rtpout')), (local + 1, ('rtcpin', 'rtcpout'))]:
            elements = [self.pipeline.get_by_name(n) for n in names]
            if any(elements):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((self.cfg['sip']['bind'], port))
                    gio_socket = Gio.Socket.new_from_fd(sock.detach())
                finally:
                    sock.close()
                self.sockets.append(gio_socket)
                for element in elements:
                    if element:
                        element.set_property('socket', gio_socket)
                        element.set_property('close-socket', False)
        rtp = self.pipeline.get_by_name('rtp')
        rtp.connect('request-pt-map', lambda obj, session, payload: caps_obj if payload == pt else None)
        def added(obj, pad):
            if pad.get_name().startswith('recv_rtp_src_0_'):
                queue = self.pipeline.get_by_name('incoming')
                if queue and not queue.get_static_pad('sink').is_linked():
                    pad.link(queue.get_static_pad('sink'))
        rtp.connect('pad-added', added)
        if receive:
            self.pipeline.get_by_name('rtpin').set_property('caps', caps_obj)
        for element, key in [('sent', 'sent_rtp'), ('received', 'received_rtp'), ('decoded', 'decoded_buffers'),
                             ('rtcpsent', 'sent_rtcp'), ('rtcpreceived', 'received_rtcp')]:
            obj = self.pipeline.get_by_name(element)
            if obj:
                obj.connect('handoff', self._count(key))
        if send and name == 'G729':
            self.bridge = G729Encoder(self.pipeline.get_by_name('encoded'))
            self.pipeline.get_by_name('pcm').connect('new-sample', self._pcm)
        if name == 'AV1':
            if send:
                self.pipeline.get_by_name('av1out').connect('new-sample', self._av1_send)
            if receive:
                self.pipeline.get_by_name('av1in').connect('new-sample', self._av1_receive)

    def _pcm(self, sink):
        try:
            data, buf = sample_bytes(sink)
            if data is not None:
                self.bridge.push(data, buf.pts)
            return Gst.FlowReturn.OK
        except Exception as exc:
            self.error = f'G729: {exc}'
            return Gst.FlowReturn.ERROR

    def _av1_send(self, sink):
        try:
            data, buf = sample_bytes(sink)
            if data is not None:
                for packet in self.pay.packets(data, buf.pts):
                    self.pipeline.get_by_name('av1rtp').emit('push-buffer', raw_buffer(packet, buf.pts))
            return Gst.FlowReturn.OK
        except Exception as exc:
            self.error = f'AV1 encoder bridge: {exc}'
            return Gst.FlowReturn.ERROR

    def _av1_receive(self, sink):
        data, buf = sample_bytes(sink)
        if data is not None:
            try:
                for frame in self.depay.push(data):
                    self.pipeline.get_by_name('av1decoded').emit('push-buffer', raw_buffer(frame))
            except ValueError:
                # Bad/incomplete RTP is not allowed to terminate the receive loop.
                self.depay = Depayloader()
        return Gst.FlowReturn.OK

    def start(self):
        if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
            # State changes often fail synchronously for permissions/display
            # problems; preserve the actual GStreamer error for the operator.
            self.poll()
            raise RuntimeError(f'{self.kind}: cannot start media pipeline')

    def poll(self):
        bus = self.pipeline.get_bus()
        while True:
            msg = bus.pop_filtered(Gst.MessageType.ERROR | Gst.MessageType.WARNING | Gst.MessageType.EOS)
            if not msg:
                break
            if msg.type == Gst.MessageType.ERROR:
                error, debug = msg.parse_error()
                self.error = f'{self.kind}/{self.codec}: {error.message} ({debug})'
            elif msg.type == Gst.MessageType.WARNING:
                error, _ = msg.parse_warning()
                self.log(f'Media warning: {error.message}')
            elif msg.type == Gst.MessageType.EOS:
                self.error = f'{self.kind}: device stream ended'
        if self.error:
            raise RuntimeError(self.error)

    def close(self):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline.get_state(2 * Gst.SECOND)
        if self.bridge:
            self.bridge.close()
            self.bridge = None
        for sock in self.sockets:
            sock.close()
        self.sockets.clear()


class Media:
    def __init__(self, cfg, selected, log=print):
        self.streams = []
        try:
            for choice in selected:
                if choice and choice[0].direction != 'inactive' and choice[0].ip != '0.0.0.0':
                    self.streams.append(MediaStream(cfg, choice, log))
            for stream in self.streams:
                stream.start()
        except Exception:
            self.close()
            raise

    def poll(self):
        for stream in self.streams:
            stream.poll()

    def mute(self, value):
        for stream in self.streams:
            volume = stream.pipeline.get_by_name('microphone')
            if volume:
                volume.set_property('mute', value)

    def stats(self):
        return {s.kind + '/' + s.codec: dict(s.stats) for s in self.streams}

    def close(self):
        for stream in self.streams:
            stream.close()
        self.streams.clear()
