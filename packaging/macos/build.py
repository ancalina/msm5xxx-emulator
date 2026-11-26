#!/usr/bin/env python3
"""Build a complete DMG, Sparkle update archive and EdDSA-signed appcast."""
from pathlib import Path
import argparse
import hashlib
import os
import plistlib
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen
from dylibs import bundle

ROOT=Path(__file__).resolve().parents[2]
PYTHON_URL='https://github.com/astral-sh/python-build-standalone/releases/download/20261123/cpython-3.12.16%2B20261123-x86_64-apple-darwin-install_only_stripped.tar.gz'
PYTHON_SHA='da628e539cebac13f43a3dc42dd99826aeab254387d3bc43478a73267a362713'
SPARKLE_URL='https://github.com/sparkle-project/Sparkle/releases/download/2.10.1/Sparkle-2.10.1.tar.xz'
SPARKLE_SHA='1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27'

def run(*args,**kwargs):subprocess.run([str(a) for a in args],check=True,**kwargs)

def download(url,sha,path):
    if not path.exists():
        temporary=path.with_suffix('.download')
        try:
            with urlopen(url,timeout=60) as source,temporary.open('wb') as target: shutil.copyfileobj(source,target)
            temporary.replace(path)
        finally: temporary.unlink(missing_ok=True)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise RuntimeError('Download checksum mismatch: '+path.name)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',required=True);p.add_argument('--build-number',required=True,type=int)
    p.add_argument('--qemu',required=True,type=Path);p.add_argument('--qemu-source',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--adhoc',action='store_true');p.add_argument('--download-prefix')
    a=p.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',a.version):p.error('Invalid version')
    if not a.adhoc:
        for key in ['MSM5XXX_SIGN_IDENTITY','MSM5XXX_NOTARY_PROFILE']:
            if not os.environ.get(key):p.error('Set '+key+'; use --adhoc only for local testing')
    if not os.environ.get('SPARKLE_PUBLIC_KEY'):p.error('Set SPARKLE_PUBLIC_KEY from Sparkle generate_keys -p')
    output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
    work=output/'.work';work.mkdir(exist_ok=True);(work/'tmp').mkdir(exist_ok=True)
    env=dict(os.environ,TMPDIR=str(work/'tmp'),MSM5XXX_APP_VERSION=a.version,MSM5XXX_BUILD_NUMBER=str(a.build_number))
    if a.adhoc:env['MSM5XXX_SIGN_IDENTITY']='-'
    application=work/'MSM5xxx Emulator.app';shutil.rmtree(application,ignore_errors=True)
    env['MSM5XXX_APP_OUTPUT']=str(application)
    run(ROOT/'desktop/macos/build-app.sh',env.get('MSM5XXX_BUILD_CONFIGURATION','release'),env=env)
    runtime=application/'Contents/Resources/runtime';(runtime/'bin').mkdir(parents=True)
    shutil.copy2(a.qemu,runtime/'bin/qemu-system-arm')
    dependencies=bundle(runtime/'bin/qemu-system-arm',runtime/'lib')
    archive=work/'python.tar.gz';download(PYTHON_URL,PYTHON_SHA,archive)
    with tarfile.open(archive) as tar:tar.extractall(runtime,filter='data')
    python=runtime/'python/bin/python3'
    run(python,'-m','pip','install','--disable-pip-version-check','--no-compile','--no-cache-dir','capstone==5.0.9','Pillow==12.3.0',env=env)
    # Runtime traces cover library, firmware/audio, settings, capture and updates.
    # The executable is statically linked; no shipped Mach-O depends on libpython.
    for relative in ['include','lib/libpython3.12.dylib','lib/python3.12/ensurepip',
                     'lib/python3.12/idlelib','lib/python3.12/pydoc_data',
                     'lib/python3.12/site-packages/pip']:
        path=runtime/'python'/relative
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink(missing_ok=True)
    for path in list((runtime/'python/bin').glob('pip*'))+list((runtime/'python/lib/python3.12/site-packages').glob('pip-*.dist-info')):
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink()
    shutil.copytree(ROOT/'src',runtime/'src',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    licenses=runtime/'licenses';licenses.mkdir()
    for name in ['LICENSE','THIRD_PARTY_NOTICES.md']:shutil.copy2(ROOT/name,licenses/name)
    for name in ['COPYING','COPYING.LIB']:shutil.copy2(a.qemu_source/name,licenses/('QEMU_'+name))
    packages=set()
    # Homebrew stores formula license identifiers in each installed receipt.
    for original in dependencies.values():
        cellar=Path('/usr/local/Cellar')
        if original.is_relative_to(cellar):
            formula,version=original.relative_to(cellar).parts[:2]
            prefix=cellar/formula/version; packages.add(formula+' '+version)
            target=licenses/'homebrew'/prefix.parent.name;target.mkdir(parents=True,exist_ok=True)
            receipt=prefix/'INSTALL_RECEIPT.json'
            if receipt.exists():shutil.copy2(receipt,target/receipt.name)
            for directory in ['share/licenses','share/doc']:
                if (prefix/directory).exists():shutil.copytree(prefix/directory,target/directory,dirs_exist_ok=True)
    (licenses/'HOMEBREW_PACKAGES.txt').write_text(''.join(name+'\n' for name in sorted(packages)))
    run(ROOT/'packaging/macos/sign.sh',application,env=env)
    run(python,'-B','-s','-c','import ctypes,capstone,PIL; callback=ctypes.CFUNCTYPE(ctypes.c_int)(lambda:7); assert callback()==7; print("Signed embedded dependencies and ctypes callback OK")',env=env)
    run(runtime/'bin/qemu-system-arm','-M','none','-cpu','arm926','-accel','tcg','-display','none','-S','-monitor','stdio',input='quit\n',text=True,env=env)
    run('codesign','--verify','--deep','--strict',application)
    if not a.adhoc:
        # Notarize the complete app before making its update archive and DMG.
        notarize=work/'notarize.zip';notarize.unlink(missing_ok=True)
        run('ditto','-c','-k','--sequesterRsrc','--keepParent',application,notarize)
        run('xcrun','notarytool','submit',notarize,'--keychain-profile',env['MSM5XXX_NOTARY_PROFILE'],'--wait')
        run('xcrun','stapler','staple',application)
        run('spctl','--assess','--type','execute','--verbose=2',application)
    stage=work/'dmg';shutil.rmtree(stage,ignore_errors=True);stage.mkdir()
    run('ditto',application,stage/application.name);(stage/'Applications').symlink_to('/Applications')
    dmg=output/f'MSM5xxx-{a.version}-macos-x86_64.dmg';dmg.unlink(missing_ok=True)
    run('hdiutil','create','-volname','MSM5xxx Emulator','-srcfolder',stage,'-format','ULFO',dmg)
    if not a.adhoc:
        run('codesign','--sign',env['MSM5XXX_SIGN_IDENTITY'],'--timestamp',dmg)
        run('xcrun','notarytool','submit',dmg,'--keychain-profile',env['MSM5XXX_NOTARY_PROFILE'],'--wait')
        run('xcrun','stapler','staple',dmg)
    updates=work/'updates';updates.mkdir(exist_ok=True)
    update=updates/f'MSM5xxx-{a.version}-macos-x86_64.zip';update.unlink(missing_ok=True)
    run('ditto','-c','-k','--sequesterRsrc','--keepParent',application,update)
    sparkle=work/'sparkle';sparkle.mkdir(exist_ok=True)
    archive=work/'Sparkle.tar.xz';download(SPARKLE_URL,SPARKLE_SHA,archive)
    with tarfile.open(archive) as tar:tar.extractall(sparkle,filter='data')
    args=[sparkle/'bin/generate_appcast','--download-url-prefix',a.download_prefix or f'https://github.com/ancalina/msm5xxx-emulator/releases/download/v{a.version}/']
    if env.get('SPARKLE_KEY_FILE'):args+=['--ed-key-file',env['SPARKLE_KEY_FILE']]
    elif env.get('SPARKLE_KEY_ACCOUNT'):args+=['--account',env['SPARKLE_KEY_ACCOUNT']]
    # shortcut: Sparkle 2.10 has no cache-directory flag; use Foundation’s tool-only
    # home override until Sparkle exposes a cache path. The actual login keychain stays unchanged.
    appcast_env=dict(env,CFFIXED_USER_HOME=str(work/'sparkle-home'))
    run(*args,updates,env=appcast_env)
    shutil.copy2(update,output/update.name);shutil.copy2(updates/'appcast.xml',output/'appcast.xml')
    print('MACOS PACKAGES OK '+a.version+(' (ad-hoc; not for distribution)' if a.adhoc else ''))

if __name__=='__main__':main()
