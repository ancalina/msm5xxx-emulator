#!/usr/bin/env python3
"""Exercise a packaged backend with owner-supplied firmware and record runtime imports."""
import argparse
import base64
import faulthandler
import json
import os
from pathlib import Path
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware',required=True,type=Path)
    parser.add_argument('--qemu',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--press',type=int,action='append',default=[])
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    faulthandler.dump_traceback_later(120,repeat=True)
    os.environ['MSM5XXX_STATE_DIR']=str(args.output/'state')
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    from msm5xxx_emulator.update import REPOSITORY
    from msm5xxx_emulator.backend.server import Backend
    from msm5xxx_emulator.backend import session
    from msm5xxx_emulator.qemu.transport import Transport
    from PIL import Image
    # Capture the real PCM channel without requiring a physical speaker in the test session.
    def streamed(*values,**kwargs):
        return Transport(*values,**kwargs,audio_stream=True)
    session.Transport=streamed
    backend=Backend(args.qemu.resolve());audio=bytearray();audio_nonzero=False;frame=None;result={}
    try:
        backend.library_add_file(str(args.firmware.resolve()))
        entries=backend.library_scan()['entries']
        assert any(entry['available'] for entry in entries),'No available library entry'
        result['library']='PASS';print('LIBRARY PASS',flush=True);backend.settings_get()
        backend.settings_set('persistent_state',False)
        backend.settings_set('ui_language','en')
        backend.session_open(str(args.firmware.resolve()))
        result['started']=backend.session_start();print('STARTED '+result['started']['title'],flush=True)
        print('SETTINGS BEGIN',flush=True)
        assert backend.session_settings()['sections'],'No hardware settings'
        print('SETTINGS PASS',flush=True)
        deadline=time.monotonic()+180
        key_deadline=time.monotonic()+90; pending_keys=list(args.press)
        while time.monotonic()<deadline:
            if pending_keys and time.monotonic()>=key_deadline:
                bit=pending_keys.pop(0)
                assert backend.session_key(bit,True),f'Key unavailable: {bit}'
                time.sleep(.3);backend.session_key(bit,False);key_deadline=time.monotonic()+3
            state=backend.session_frame()
            assert state['running'],'QEMU exited during boot'
            if state.get('rgb') and state['seq']>0:frame=state
            transport=backend.session.transport
            while record:=transport.take_native_audio(timeout=0):
                payload=record[32:];audio.extend(payload);audio_nonzero=audio_nonzero or any(payload)
            if frame and len(audio)>4096 and audio_nonzero:break
            time.sleep(.01)
        assert frame is not None,'No display frame from real firmware'
        Image.frombytes('RGB',(frame['width'],frame['height']),base64.b64decode(frame['rgb'])).save(args.output/'capture.png')
        result['capture']='PASS';result['audio_bytes']=len(audio);result['audio_nonzero']=audio_nonzero
        result['audio_status']=backend.session.transport.audio_stream_status
        result['state']=backend.session_state()
        (args.output/'audio.pcm').write_bytes(audio)
        feed=args.output/'feed.json';feed.write_text(json.dumps({'tag_name':'v0.2.0-rc','html_url':f'https://github.com/{REPOSITORY}/releases/tag/v0.2.0-rc','assets':[]}))
        os.environ['MSM5XXX_UPDATE_FEED']=str(feed)
        backend.updates_check('0.1.99');result['update_check']='PASS'
        assert audio and audio_nonzero,'No nonzero audio captured from real firmware'
        result['result']='PASS'
    finally:
        if backend.session is not None:backend.session_stop()
        modules={name:str(getattr(module,'__file__','')) for name,module in sorted(sys.modules.items())}
        (args.output/'modules.json').write_text(json.dumps(modules,indent=2)+'\n')
        (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PACKAGED BACKEND BOOT AUDIO SETTINGS CAPTURE UPDATE PASS',flush=True)

if __name__=='__main__':main()
