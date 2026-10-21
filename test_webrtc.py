"""Synthetic bidirectional WebRTC checks; no registration or physical devices."""
import asyncio
import copy
import json
import tomllib
from pathlib import Path
from webrtc_media import WebRTCMedia

async def main():
    cfg = tomllib.loads(Path(__file__).with_name('config.example.toml').read_text())
    cfg['media']['test'] = True
    for audio, video in [('PCMU', 'VP8'), ('PCMA', None), ('PCMU', 'H264')]:
        cfg['webrtc']['audio_codec'] = audio
        cfg['webrtc']['video_codec'] = video or 'VP8'
        other = copy.deepcopy(cfg)
        other['webrtc'].update(ice_min_port=41200, ice_max_port=41300)
        peers = [WebRTCMedia(cfg), WebRTCMedia(other)]
        try:
            offer = await peers[0].offer(bool(video))
            answer = await peers[1].answer(offer)
            await peers[0].accept_answer(answer)
            async with asyncio.timeout(15):
                while True:
                    for peer in peers:
                        peer.poll()
                    if all(all(v > 10 for k, v in p.counters.items() if 'decoded_buffers' in k)
                           and p.stats()['webrtc']['connection'] == 'connected' for p in peers):
                        break
                    await asyncio.sleep(.1)
            print(audio, video, json.dumps([p.stats() for p in peers]), flush=True)
        finally:
            for peer in peers:
                peer.close()
    print('PASS: WebRTC PCMU/VP8, PCMA audio, PCMU/H264 in both directions')

if __name__ == '__main__':
    asyncio.run(main())
