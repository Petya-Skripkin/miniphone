"""Protocol regression tests; stdlib only, no real SIP server or devices."""
import asyncio
import copy
import hashlib
import re
import socket
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
from settings import load
from sip import Message, Endpoint, digest, tag
from phone import Phone
from av1rtp import Payloader, Depayloader, leb, unleb
import sdp


def configuration(port=15060, rtp=41000):
    cfg = tomllib.loads(Path(__file__).with_name('config.example.toml').read_text(encoding='utf-8'))
    cfg['sip'].update(transport='udp', server='127.0.0.1', server_ip='127.0.0.1', domain='127.0.0.1',
                      bind='127.0.0.1', advertise_ip='127.0.0.1', local_port=port, port=15069,
                      username=str(port), auth_username='test', password='secret', register=False)
    cfg['media'].update(test=True, rtp_port=rtp, width=320, height=240, fps=10)
    return cfg


class FakeMedia:
    def __init__(self, cfg, selected, log):
        self.closed = False
    def close(self): self.closed = True
    def poll(self): pass
    def stats(self): return {}
    def mute(self, value): pass


async def until(condition, seconds=3):
    async with asyncio.timeout(seconds):
        while not condition():
            await asyncio.sleep(.01)


class PureTests(unittest.TestCase):
    def test_digest_rfc2617_vector(self):
        challenge = 'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"'
        with patch('sip.token', return_value='0a4f113b'):
            auth = digest(challenge, 'Mufasa', 'Circle Of Life', 'GET', '/dir/index.html')
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', auth)

    def test_message_compact_and_utf8_length(self):
        msg = Message('SIP/2.0 200 OK', [('v', 'x'), ('f', 'a'), ('t', 'b'), ('i', 'id'), ('CSeq', '1 INVITE')], 'привет')
        parsed = Message.parse(msg.wire())
        self.assertEqual(parsed.body, 'привет')
        self.assertEqual(parsed.get('Via'), 'x')
        with self.assertRaises(ValueError):
            Message.parse(msg.wire().replace(b'Content-Length: 12', b'Content-Length: 100'))

    def test_sdp_allowlist_and_rejected_m_lines(self):
        cfg = configuration()
        offer = sdp.make(cfg)
        self.assertNotIn('opus', offer.lower())
        parsed = sdp.parse(offer)
        self.assertEqual(set(parsed[0].codecs.values()), {'PCMU', 'PCMA', 'G722', 'G729'})
        parsed.append(sdp.Stream('application', 45000, 'RTP/AVP', [110], '127.0.0.1'))
        choices = sdp.choose(parsed, cfg)
        answer = sdp.make(cfg, (parsed, choices))
        self.assertIn('m=application 0 RTP/AVP 110', answer)
        self.assertIn('a=fmtp:96 packetization-mode=1', answer)

    def test_bad_sdp_and_disabled_video(self):
        cfg = configuration()
        offer = sdp.make(cfg)
        cfg['media']['video'] = False
        choices = sdp.choose(sdp.parse(offer), cfg)
        self.assertIsNone(choices[1])
        with self.assertRaises(ValueError):
            sdp.parse(offer.replace('IN IP4 127.0.0.1', 'IN IP4 invalid'))

    def test_pbx_extra_telephone_event_is_not_selected(self):
        cfg = configuration()
        offer = sdp.make(cfg, video=False)
        answer = offer.replace('RTP/AVP 0 8 9 18', 'RTP/AVP 0 101') + 'a=rtpmap:101 telephone-event/8000\r\n'
        parsed = sdp.parse(answer)
        sdp.validate_answer(parsed, sdp.parse(offer))
        self.assertEqual(sdp.choose(parsed, cfg)[0][2], 'PCMU')
        self.assertNotIn(101, parsed[0].codecs)

    def test_av1_fragmentation_extensions_padding_and_loss(self):
        obu = bytes([0x32]) + leb(5000) + b'x' * 5000
        pay = Payloader(98, mtu=300)
        packets = list(pay.packets(obu, 0))
        self.assertGreater(len(packets), 10)
        depay = Depayloader()
        frames = [frame for p in packets for frame in depay.push(p)]
        self.assertEqual(frames, [obu])
        depay = Depayloader()
        frames = [frame for p in packets[:2] + packets[3:] for frame in depay.push(p)]
        self.assertEqual(frames, [])
        for p in pay.packets(obu, 100000000):
            frames.extend(depay.push(p))
        self.assertEqual(frames, [obu])
        single = next(Payloader(98).packets(b'\x32\x03abc', 0))
        ext = bytes([single[0] | 0x30]) + single[1:12] + b'\xbe\xde\x00\x01xxxx' + single[12:] + b'\x00\x00\x00\x04'
        self.assertEqual(Depayloader().push(ext), [b'\x32\x03abc'])

    def test_av1_aggregation_w0(self):
        import struct
        a, b = b'\x08a', b'\x30bc'
        packet = struct.pack('!BBHII', 128, 128 | 98, 1, 0, 7) + b'\x08' + leb(len(a)) + a + leb(len(b)) + b
        self.assertEqual(Depayloader().push(packet), [b'\x0a\x01a\x32\x02bc'])


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.logs = []
        self.a = Phone(configuration(), self.logs.append, FakeMedia)
        self.b = Phone(configuration(15062, 41004), self.logs.append, FakeMedia)
        await self.a.start(); await self.b.start()

    async def asyncTearDown(self):
        await self.a.close(); await self.b.close()

    async def connect_pair(self):
        task = asyncio.create_task(self.a.dial('sip:15062@127.0.0.1:15062'))
        await until(lambda: self.b.call and self.b.call['state'] == 'ringing')
        await self.b.answer()
        await task
        await until(lambda: self.b.call['state'] == 'active')
        self.assertEqual(self.a.call['state'], 'active')

    async def test_incoming_outgoing_ack_bye_and_reverse(self):
        await self.connect_pair()
        media_a, media_b = self.a.call['media'], self.b.call['media']
        await self.a.hangup()
        await until(lambda: self.b.call is None)
        self.assertTrue(media_a.closed and media_b.closed)
        task = asyncio.create_task(self.b.dial('sip:15060@127.0.0.1:15060', video=False))
        await until(lambda: self.a.call and self.a.call['state'] == 'ringing')
        await self.a.answer(); await task
        await self.b.hangup()
        await until(lambda: self.a.call is None)

    async def test_cancel_and_reject(self):
        task = asyncio.create_task(self.a.dial('sip:15062@127.0.0.1:15062'))
        await until(lambda: self.b.call and self.a.call['provisional'])
        await self.a.hangup(); await task
        await until(lambda: self.b.call is None)
        self.assertIsNone(self.a.call)
        task = asyncio.create_task(self.a.dial('sip:15062@127.0.0.1:15062'))
        await until(lambda: self.b.call)
        await self.b.reject(); await task
        self.assertIsNone(self.a.call)

    async def test_auto_answer(self):
        self.b.cfg['media']['auto_answer'] = True
        await self.a.dial('sip:15062@127.0.0.1:15062')
        await until(lambda: self.b.call and self.b.call['state'] == 'active')
        self.assertEqual(self.a.call['state'], 'active')

    async def test_busy_and_spoofed_bye(self):
        await self.connect_pair()
        req = self.a.sip.request('INVITE', 'sip:15062@127.0.0.1:15062', body=sdp.make(self.a.cfg))
        res = await self.a.sip.transact(req, ('127.0.0.1', 15062))
        self.assertEqual(res.status, 486)
        bye = self.a.sip.request('BYE', 'sip:15062@127.0.0.1:15062', self.a.call['id'])
        res = await self.a.sip.transact(bye, ('127.0.0.1', 15062))
        self.assertEqual(res.status, 481)
        self.assertEqual(self.b.call['state'], 'active')

    async def test_duplicate_invite_replays_same_response(self):
        await self.connect_pair()
        old = self.b.call['media']
        self.a.sip.send(self.a.call['req'], ('127.0.0.1', 15062))
        await asyncio.sleep(.1)
        self.assertIs(self.b.call['media'], old)
        self.assertEqual(self.b.call['state'], 'active')

    async def test_lost_invite_is_retransmitted(self):
        original = self.b.sip.datagram_received
        dropped = []
        def lossy(data, addr):
            if data.startswith(b'INVITE ') and not dropped:
                dropped.append(True)
            else:
                original(data, addr)
        self.b.sip.datagram_received = lossy
        await self.connect_pair()
        self.assertTrue(dropped)

    async def test_lost_200_is_retransmitted_and_acked(self):
        original = self.a.sip.datagram_received
        dropped = []
        def lossy(data, addr):
            msg = Message.parse(data)
            if msg.status == 200 and msg.get('CSeq').endswith(' INVITE') and not dropped:
                dropped.append(True)
            else:
                original(data, addr)
        self.a.sip.datagram_received = lossy
        await self.connect_pair()
        self.assertTrue(dropped)

    async def test_register_digest_and_unregister(self):
        registrar = Endpoint(configuration(15069)['sip'], self.logs.append)
        counts = []
        challenge = 'Digest realm="test", nonce="abc123", algorithm=MD5, qop="auth"'
        async def handler(req, addr):
            auth = req.get('Authorization')
            if not auth:
                registrar.respond(req, addr, 401, 'Unauthorized', extra=[('WWW-Authenticate', challenge)])
                return
            fields = dict((m[1], m[2] or m[3]) for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^, ]+))', auth))
            h = lambda x: hashlib.md5(x.encode()).hexdigest()
            expected = h(h('test:test:secret') + ':abc123:' + fields['nc'] + ':' + fields['cnonce'] + ':auth:' + h('REGISTER:sip:127.0.0.1'))
            self.assertEqual(fields['response'], expected)
            counts.append(int(req.get('Expires')))
            registrar.respond(req, addr, 200, 'OK', extra=[('Contact', req.get('Contact') + ';expires=' + req.get('Expires'))])
        registrar.handler = handler
        await registrar.start()
        try:
            await self.a.register()
            self.assertTrue(self.a.registered)
            await self.a.register(0)
            self.assertFalse(self.a.registered)
            self.assertEqual(counts, [300, 0])
        finally:
            await registrar.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
