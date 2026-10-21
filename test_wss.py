"""WebSocket framing and failure handling without network or extra dependencies."""
import asyncio
import struct
import unittest
from types import SimpleNamespace
from wss import WSS, frame, LIMIT

class Writer:
    def __init__(self): self.data=[]; self.closed=False
    def write(self,data): self.data.append(data)
    async def drain(self): pass
    def close(self): self.closed=True

class Tests(unittest.IsolatedAsyncioTestCase):
    def test_client_mask_and_lengths(self):
        for n in (0, 125, 126, 65535, 65536):
            payload=b'a'*n; encoded=frame(payload)
            self.assertEqual(encoded[0],0x81)
            self.assertTrue(encoded[1]&128)
            offset=2
            if n>=65536:
                self.assertEqual(struct.unpack('!Q',encoded[2:10])[0],n);offset=10
            elif n>=126:
                self.assertEqual(struct.unpack('!H',encoded[2:4])[0],n);offset=4
            mask=encoded[offset:offset+4]
            self.assertEqual(bytes(x^mask[i%4] for i,x in enumerate(encoded[offset+4:])),payload)
        with self.assertRaises(ValueError):frame(b'x'*(LIMIT+1))

    async def receive(self, data):
        messages=[]; queue=asyncio.Queue(); lost=[]
        endpoint=SimpleNamespace(cfg={'server_ip':'127.0.0.1','port':5060},
            pending={'x':queue}, log=lambda x:None, on_disconnect=lambda:lost.append(True),
            datagram_received=lambda data,addr:messages.append(data))
        transport=WSS(endpoint);reader=asyncio.StreamReader();writer=Writer();transport.writer=writer
        reader.feed_data(data);reader.feed_eof()
        await transport.read_loop(reader,writer)
        self.assertTrue(writer.closed)
        self.assertTrue(lost)
        self.assertIsInstance(queue.get_nowait(),OSError)
        return messages,writer

    async def test_fragmentation_and_ping(self):
        messages,writer=await self.receive(b'\x01\x03SIP\x89\x01?\x80\x03/2.\x81\x01x')
        self.assertEqual(messages,[b'SIP/2.',b'x'])
        self.assertEqual(writer.data[0][0],0x8a)

    async def test_invalid_frames_disconnect(self):
        for data in (b'\x81\x81', b'\x80\x01x',b'\x09\x01x',b'\x81\x7f'+struct.pack('!Q',LIMIT+1)):
            messages,_=await self.receive(data)
            self.assertEqual(messages,[])

if __name__=='__main__':unittest.main()
