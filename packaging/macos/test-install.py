#!/usr/bin/env python3
"""Install debug DMG fixtures, exercise the in-app Sparkle harness, and uninstall."""
from pathlib import Path
import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen


def run(*args,**kwargs):subprocess.run([str(arg) for arg in args],check=True,**kwargs)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',required=True,type=Path)
    parser.add_argument('--release-directory',required=True,type=Path)
    parser.add_argument('--work',required=True,type=Path)
    parser.add_argument('--port',type=int,default=8766)
    args=parser.parse_args();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    data=work/'data';data.mkdir(exist_ok=True)
    (data/'retention-test').write_text('library settings saved state')
    for name in ['library-retention.json','settings-retention.json','saved-state-retention']:
        (data/name).write_text('retained '+name)
    mount=work/'mount';mount.mkdir(exist_ok=True)
    application=work/'Applications/MSM5xxx Emulator.app';application.parent.mkdir(exist_ok=True)
    with (work/'install.log').open('w') as log:
        run('hdiutil','attach','-nobrowse','-readonly','-mountpoint',mount,args.baseline.resolve(),stdout=log,stderr=subprocess.STDOUT)
        try:
            if os.readlink(mount/'Applications')!='/Applications':raise RuntimeError('Missing standard Applications link')
            if application.exists():raise RuntimeError('Use an empty test installation directory')
            run('ditto',mount/application.name,application)
        finally:run('hdiutil','detach',mount,stdout=log,stderr=subprocess.STDOUT)
    info=plistlib.loads((application/'Contents/Info.plist').read_bytes())
    if info.get('MSM5xxxUpdateTestDirectory')!=str(work):raise RuntimeError('Debug fixture test directory does not match --work')
    if info.get('CFBundleIdentifier')!='io.github.ancalina.MSM5xxx.desktop.installertest':raise RuntimeError('Use the isolated debug test application')
    run('codesign','--verify','--deep','--strict',application)
    server=subprocess.Popen([sys.executable,'-m','http.server',str(args.port),'--bind','127.0.0.1',
        '--directory',str(args.release_directory.resolve())],stdout=(work/'feed.log').open('w'),stderr=subprocess.STDOUT)
    try:
        # Confirm the local feed is serving before Sparkle starts its short request timeout.
        deadline=time.monotonic()+120
        while True:
            if server.poll() is not None:raise RuntimeError('Local feed server exited')
            try:
                with urlopen(f'http://127.0.0.1:{args.port}/appcast.xml',timeout=3) as response:
                    if response.status!=200:raise RuntimeError('Local feed is not ready')
                break
            except OSError:
                if time.monotonic()>=deadline:raise RuntimeError('Local feed did not become ready')
                time.sleep(1)
        process=subprocess.Popen([str(application/'Contents/MacOS/MSM5xxx Emulator'),'-AppleLanguages','(en)'],
            env=dict(os.environ,MSM5XXX_STATE_DIR=str(data)),stdout=(work/'application.log').open('w'),stderr=subprocess.STDOUT)
        deadline=time.monotonic()+1800
        while time.monotonic()<deadline:
            result=work/'result.txt'
            if result.exists():
                text=result.read_text().strip()
                if text!='PASS':raise RuntimeError(text)
                break
            time.sleep(3)
        else:raise RuntimeError('Update verification did not finish')
        process.wait(timeout=120)
        info=plistlib.loads((application/'Contents/Info.plist').read_bytes())
        if info.get('CFBundleVersion')!='20000':raise RuntimeError('Installed bundle version did not advance')
        run('codesign','--verify','--deep','--strict',application)
        for name in ['library-retention.json','settings-retention.json','saved-state-retention']:
            if (data/name).read_text()!='retained '+name:raise RuntimeError('User data changed: '+name)
        # The final app quits itself after taking its updated-window snapshot.
        time.sleep(3)
        shutil.rmtree(application)
        if not (data/'retention-test').is_file():raise RuntimeError('Uninstall removed user data')
        (work/'uninstall-result.txt').write_text('PASS: app removed; library, settings and saved state retained\n')
        print('MACOS INSTALL UPDATE UNINSTALL PASS')
    finally:
        server.terminate();server.wait(timeout=30)

if __name__=='__main__':main()
