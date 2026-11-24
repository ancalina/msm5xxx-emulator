#!/usr/bin/env python3
"""Build a complete native Linux AppImage, update metadata and Debian package."""
from pathlib import Path
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import site
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
ID = 'io.github.ancalina.MSM5xxx'
TOOLS = {
 'appimagetool': ('https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage', 'e8c1169c4af66c3184d7ee110713d4be04befe671fa358e2c1591ee840553b03'),
 'runtime': ('https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64', '617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46'),
}


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def copy(source, destination):
    source, destination = Path(source), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def closure(bundle):
    # shortcut: host-built GTK requires the build host's glibc; use an older build distribution when widening the supported baseline.
    pending = [p for p in bundle.rglob('*') if p.is_file() and not p.is_symlink() and
               (p.suffix == '.so' or '.so.' in p.name or os.access(p, os.X_OK))]
    copied = set()
    packages = set()
    libraries = bundle/'lib'; libraries.mkdir(exist_ok=True)
    while pending:
        binary = pending.pop()
        with binary.open('rb') as stream:
            if stream.read(4) != b'\x7fELF': continue
        result = subprocess.run(['ldd', str(binary)], capture_output=True, text=True)
        if 'not found' in result.stdout:
            raise RuntimeError(f'Unresolved dependency in {binary}: {result.stdout}')
        for name, path in re.findall(r'^\s*(\S+)\s+=>\s+(/\S+)', result.stdout, re.M):
            if name in ('libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1', 'libresolv.so.2'):
                continue
            if name in copied: continue
            copied.add(name)
            destination = libraries/name
            if Path(path).resolve() != destination.resolve(): copy(path, destination)
            pending.append(destination)
            if str(Path(path).resolve()).startswith('/usr/lib/'):
                owner = subprocess.check_output(['dpkg-query','-S',str(Path(path).resolve())], text=True).split(': ',1)[0]
                packages.add(owner)
                notice = Path('/usr/share/doc')/owner.split(':')[0]/'copyright'
                if notice.is_file(): copy(notice,bundle/'share/doc/dependencies'/(owner.replace(':','_')+'.copyright'))
    (bundle/'PACKAGES.txt').write_text(subprocess.check_output(['dpkg-query','-W','-f=${binary:Package} ${Version}\n',*sorted(packages)],text=True))
    (bundle/'LIBRARIES.txt').write_text('\n'.join(sorted(copied))+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('version'); parser.add_argument('qemu', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?', args.version): parser.error('Invalid version')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    work = output/'.work'; work.mkdir(exist_ok=True)
    temporary = work/'tmp'; temporary.mkdir(exist_ok=True)
    os.environ.update(TMPDIR=str(temporary), APPIMAGE_EXTRACT_AND_RUN='1', ARCH='x86_64', PYTHONDONTWRITEBYTECODE='1', MSM5XXX_RELEASE_VERSION=args.version)
    os.environ.setdefault('XDG_CACHE_HOME', str(work/'cache'))
    os.environ.setdefault('CARGO_HOME', str(work/'cargo-home'))
    os.environ.setdefault('CARGO_TARGET_DIR', str(work/'target'))
    os.environ['PIP_CACHE_DIR']=str(work/'pip-cache')
    target = Path(os.environ['CARGO_TARGET_DIR']).resolve()
    run('cargo','build','--locked','--release','--manifest-path',ROOT/'desktop/linux/Cargo.toml','-j1',cwd=ROOT)
    appdir = work/'MSM5xxx.AppDir'
    if appdir.exists(): shutil.rmtree(appdir)
    bundle = appdir/'usr'
    (bundle/'bin').mkdir(parents=True)
    copy(target/'release/msm5xxx-desktop', bundle/'bin/msm5xxx-desktop')
    copy(args.qemu.resolve(), bundle/'bin/qemu-system-arm')
    shutil.copytree(ROOT/'src', bundle/'src', ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    (bundle/'VERSION').write_text(args.version+'\n')
    python = bundle/'python'
    copy(sys.executable, python/'bin/python3')
    stdlib = Path(sysconfig.get_path('stdlib'))
    shutil.copytree(stdlib, python/'lib'/stdlib.name,
        ignore=shutil.ignore_patterns('__pycache__','*.pyc','test','tests','idlelib','tkinter','_tkinter*','site-packages','dist-packages'))
    packages = Path(site.getsitepackages([str(python)])[0])
    run(sys.executable,'-m','pip','install','--disable-pip-version-check','--no-compile','--only-binary=:all:','--target',packages,'-r',ROOT/'requirements.txt')
    pixbuf = subprocess.check_output(['pkg-config','--variable=gdk_pixbuf_query_loaders','gdk-pixbuf-2.0'],text=True).strip()
    loaders = subprocess.check_output(['pkg-config','--variable=gdk_pixbuf_moduledir','gdk-pixbuf-2.0'],text=True).strip()
    copy(pixbuf,bundle/'bin/gdk-pixbuf-query-loaders')
    shutil.copytree(loaders,bundle/'lib/gdk-pixbuf')
    shutil.copytree('/usr/libexec/glycin-loaders',bundle/'libexec/glycin-loaders')
    shutil.copytree('/usr/share/glycin-loaders',bundle/'share/glycin-loaders')
    shutil.copytree('/usr/lib/x86_64-linux-gnu/gio/modules',bundle/'lib/gio/modules')
    shutil.copytree('/usr/share/glib-2.0/schemas',bundle/'share/glib-2.0/schemas')
    shutil.copytree('/usr/share/icons/Adwaita',bundle/'share/icons/Adwaita',symlinks=True)
    shutil.copytree(target/'release/msm5xxx-icons/hicolor',bundle/'share/icons/hicolor')
    copy('/usr/share/icons/hicolor/index.theme',bundle/'share/icons/hicolor/index.theme')
    copy(ROOT/'desktop/linux/data'/f'{ID}.desktop',bundle/'share/applications'/f'{ID}.desktop')
    locale = bundle/'share/locale/ko/LC_MESSAGES'; locale.mkdir(parents=True)
    run('msgfmt','--check',ROOT/'desktop/linux/po/ko.po','-o',locale/'msm5xxx.mo')
    copy(ROOT/'packaging/linux/AppRun', appdir/'AppRun'); (appdir/'AppRun').chmod(0o755)
    copy(ROOT/'packaging/linux/runtime.py',bundle/'libexec/msm5xxx/runtime.py')
    for name in ('adwaita-icon-theme','python3.14','glycin-loaders'):
        copy(Path('/usr/share/doc')/name/'copyright',bundle/'share/doc/dependencies'/(name+'.copyright'))
    for domain in ('gtk40','libadwaita','glib20','gdk-pixbuf'):
        source=Path('/usr/share/locale/ko/LC_MESSAGES')/(domain+'.mo')
        if source.is_file(): copy(source,locale/source.name)
    qemu_source=args.qemu.resolve().parent.parent/'qemu-10.2.1-msm5xxx'
    for name in ('COPYING','COPYING.LIB'):
        copy(qemu_source/name,bundle/'share/doc/msm5xxx'/('QEMU_'+name))
    copy(ROOT/'LICENSE',bundle/'share/doc/msm5xxx/LICENSE')
    copy(ROOT/'THIRD_PARTY_NOTICES.md',bundle/'share/doc/msm5xxx/THIRD_PARTY_NOTICES.md')
    copy(ROOT/'desktop/linux/data'/f'{ID}.desktop',appdir/f'{ID}.desktop')
    copy(bundle/'share/icons/hicolor/256x256/apps'/f'{ID}.png',appdir/f'{ID}.png')
    (appdir/'.DirIcon').symlink_to(f'{ID}.png')
    metadata=bundle/'share/metainfo'/f'{ID}.metainfo.xml'
    metadata.parent.mkdir(parents=True,exist_ok=True)
    metadata.write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
 <id>{ID}</id><metadata_license>CC0-1.0</metadata_license><project_license>GPL-2.0-or-later</project_license>
 <name>MSM5xxx Emulator</name><summary>Run and preserve feature-phone firmware</summary>
 <description><p>Import your own firmware into a library and run it in a native desktop emulator. Firmware and optional sound-chip ROM files are user-supplied.</p></description>
 <launchable type="desktop-id">{ID}.desktop</launchable><pkgname>msm5xxx-emulator</pkgname>
 <url type="homepage">https://github.com/ancalina/msm5xxx-emulator</url>
 <provides><binary>msm5xxx-desktop</binary></provides>
</component>
''')
    closure(bundle)
    runtime_env=dict(os.environ, PYTHONHOME=str(python), PYTHONPATH=str(bundle/'src'), PYTHONNOUSERSITE='1', LD_LIBRARY_PATH=str(bundle/'lib'))
    run(python/'bin/python3','-c','import capstone, PIL, numpy, msm5xxx_emulator.backend',env=runtime_env)
    run(bundle/'bin/qemu-system-arm','--version',env=runtime_env)
    for name,(url,digest) in TOOLS.items():
        tool = work/name
        if not tool.exists():
            with urlopen(url,timeout=60) as source, tool.open('wb') as destination: shutil.copyfileobj(source,destination)
        with tool.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=digest: raise RuntimeError(f'{name}: checksum mismatch')
        tool.chmod(0o755)
    image = output/f'MSM5xxx-{args.version}-linux-x86_64.AppImage'
    update = 'gh-releases-zsync|ancalina|msm5xxx-emulator|latest|MSM5xxx-*-linux-x86_64.AppImage.zsync'
    image.unlink(missing_ok=True)
    run(work/'appimagetool','--runtime-file',work/'runtime','-u',update,appdir,image,cwd=output)
    run('zsyncmake','-u',f'https://github.com/ancalina/msm5xxx-emulator/releases/download/v{args.version}/{image.name}','-o',str(image)+'.zsync',image)
    deb = work/'deb'
    if deb.exists(): shutil.rmtree(deb)
    shutil.copytree(appdir,deb/'opt/msm5xxx',symlinks=True)
    (deb/'usr/bin').mkdir(parents=True)
    (deb/'usr/bin/msm5xxx-desktop').symlink_to('../../opt/msm5xxx/AppRun')
    copy(bundle/'share/applications'/f'{ID}.desktop',deb/'usr/share/applications'/f'{ID}.desktop')
    shutil.copytree(bundle/'share/icons/hicolor',deb/'usr/share/icons/hicolor')
    copy(metadata,deb/'usr/share/metainfo'/metadata.name)
    (deb/'DEBIAN').mkdir()
    (deb/'DEBIAN/control').write_text(f'Package: msm5xxx-emulator\nVersion: {args.version.replace("-","~",1)}\nArchitecture: amd64\nMaintainer: Ancalina <78996985+ancalina@users.noreply.github.com>\nDepends: libc6 (>= 2.43)\nSection: games\nPriority: optional\nDescription: Native feature-phone emulator\n Includes QEMU, GTK 4, libadwaita and Python. Firmware is user-supplied.\n')
    run('dpkg-deb','--root-owner-group','--build',deb,output/f'MSM5xxx-{args.version}-linux-amd64.deb')
    print(f'LINUX PACKAGES OK {args.version}',flush=True)


if __name__ == '__main__': main()
