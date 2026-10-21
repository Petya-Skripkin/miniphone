"""Actual two-way UDP RTP/RTCP encoding/decoding tests for all seven codecs.

No microphone/camera required. Uses test tone, moving picture and fake sinks.
"""
import asyncio
import json
import socket
from test_phone import configuration, until
from sdp import Stream
from settings import AUDIO, VIDEO
from media import Media
from phone import Phone


async def codec_test(codec, index):
    kind = 'audio' if codec in AUDIO else 'video'
    pt, _ = (AUDIO | VIDEO)[codec]
    left, right = configuration(rtp=42000 + index * 8), configuration(rtp=42004 + index * 8)
    offset = 0 if kind == 'audio' else 2
    def selected(cfg):
        stream = Stream(kind, cfg['media']['rtp_port'] + offset, 'RTP/AVP', [pt], '127.0.0.1', {pt: codec})
        stream.rtcp = stream.port + 1
        return [(stream, pt, codec)]
    a = b = None
    try:
        a = Media(left, selected(right))
        b = Media(right, selected(left))
        deadline = asyncio.get_running_loop().time() + 12
        while asyncio.get_running_loop().time() < deadline:
            a.poll(); b.poll()
            sa, sb = next(iter(a.stats().values())), next(iter(b.stats().values()))
            if all(s['decoded_buffers'] >= 10 and s['sent_rtp'] >= 10 and s['received_rtp'] >= 10
                   and s['received_rtcp'] >= 1 for s in (sa, sb)):
                print(json.dumps({'codec': codec, 'result': 'PASS', 'left': sa, 'right': sb}), flush=True)
                return
            await asyncio.sleep(.1)
        raise AssertionError(f'{codec}: insufficient decoded media / RTCP: {a.stats()} / {b.stats()}')
    finally:
        if a: a.close()
        if b: b.close()


async def sip_media_test():
    a = Phone(configuration(15160, 43000))
    b = Phone(configuration(15162, 43004))
    await a.start(); await b.start()
    try:
        task = asyncio.create_task(a.dial('sip:15162@127.0.0.1:15162'))
        await until(lambda: b.call and b.call['state'] == 'ringing')
        await b.answer(); await task
        await until(lambda: b.call['state'] == 'active')
        await until(lambda: all(s['decoded_buffers'] >= 10 for p in (a, b) for s in p.status()['media'].values()), 10)
        assert a.call and b.call and len(a.status()['media']) == 2 and len(b.status()['media']) == 2
        print(json.dumps({'sip_audio_video': 'PASS', 'left': a.status(), 'right': b.status()}), flush=True)
        await b.hangup()
        await until(lambda: a.call is None)
    finally:
        await a.close(); await b.close()


async def main():
    # A symmetric-RTP PBX sends return packets to the sender's source port.
    cfg = configuration(rtp=44000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1', 44004)); receiver.settimeout(3)
        stream = Stream('audio', 44004, 'RTP/AVP', [0], '127.0.0.1', {0: 'PCMU'}, direction='recvonly', rtcp=44005)
        media = Media(cfg, [(stream, 0, 'PCMU')])
        try:
            packet, addr = await asyncio.to_thread(receiver.recvfrom, 1500)
            assert addr[1] == 44000, f'Source port is {addr[1]}, expected 44000'
            print('Symmetric RTP source port: PASS', flush=True)
        finally:
            media.close()
    for index, codec in enumerate(list(AUDIO) + list(VIDEO)):
        await codec_test(codec, index)
    await sip_media_test()


if __name__ == '__main__':
    asyncio.run(main())
