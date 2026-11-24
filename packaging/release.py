#!/usr/bin/env python3
"""Build installers and update metadata from a checked-out release tag."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import shlex
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def run(*arguments,**kwargs):
    subprocess.run([str(arg) for arg in arguments],check=True,**kwargs)


def output(*arguments):
    return subprocess.check_output([str(arg) for arg in arguments],text=True,cwd=ROOT).strip()


def release_version(tag):
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',tag):
        raise ValueError('Use a vMAJOR.MINOR.PATCH release tag, optionally with a prerelease suffix')
    return tag[1:]


def source(tag):
    commit=output('git','rev-parse',tag+'^{commit}')
    if commit!=output('git','rev-parse','HEAD'):
        raise ValueError('Check out the requested release tag before building')
    if output('git','status','--porcelain','--untracked-files=no'):
        raise ValueError('Tracked source changes must be committed before a release build')
    return commit


def digest(path):
    result=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):result.update(block)
    return result.hexdigest()


def manifest(directory,version,commit,target,dry_run):
    suffixes={'windows':('.exe','.nupkg'),'linux':('.AppImage','.zsync','.deb'),
              'macos':('.dmg','.zip'),'android':('.apk',)}[target]
    metadata={'windows':{'releases.win.json'},'macos':{'appcast.xml'},'linux':set(),
              'android':{'MSM5xxx-QEMU-android-runtime-sources.tar.xz'}}[target]
    files=[{'name':p.name,'size':p.stat().st_size,'sha256':digest(p)}
           for p in sorted(directory.iterdir()) if p.is_file() and (p.name.endswith(suffixes) or p.name in metadata)]
    if not files:raise RuntimeError('No release artifacts were produced')
    (directory/'release.json').write_text(json.dumps({'version':version,'commit':commit,'platform':target,
        'dry_run':dry_run,'files':files},indent=2)+'\n')
    (directory/'SHA256SUMS').write_text(''.join(f"{f['sha256']}  {f['name']}\n" for f in files))


def build(args):
    version=release_version(args.tag);commit=source(args.tag)
    destination=args.output.resolve();destination.mkdir(parents=True,exist_ok=True)
    work=destination/'.work';work.mkdir(exist_ok=True);(work/'tmp').mkdir(exist_ok=True)
    env=dict(os.environ,TMPDIR=str(work/'tmp'),PYTHONDONTWRITEBYTECODE='1',
             BUILD_COMMIT=commit,MSM5XXX_APP_COMMIT=commit,MSM5XXX_APP_VERSION=version,
             MSM5XXX_RELEASE_VERSION=version,SOURCE_DATE_EPOCH=output('git','show','-s','--format=%ct',commit))
    if args.platform=='windows':
        if platform.system()!='Windows':raise ValueError('Build Windows installers on Windows')
        if not args.runtime:raise ValueError('--runtime must identify the QEMU runtime made by packaging/windows/build-qemu.sh')
        if args.previous:
            # Velopack computes deltas against a previous complete package; never invent a baseline.
            for file in args.previous.glob('*.nupkg'):shutil.copy2(file,destination/file.name)
            feed=args.previous/'releases.win.json'
            if feed.is_file():shutil.copy2(feed,destination/feed.name)
        run('powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',ROOT/'packaging/windows/build.ps1',
            '-Version',version,'-RuntimeDirectory',args.runtime.resolve(),'-OutputDirectory',destination,env=env,cwd=ROOT)
    elif args.platform=='linux':
        if platform.system()!='Linux':raise ValueError('Build Linux installers on Linux')
        if not args.qemu:raise ValueError('--qemu must identify the current project QEMU build')
        run(sys.executable,ROOT/'packaging/linux/build.py',version,args.qemu.resolve(),destination,env=env,cwd=ROOT)
    elif args.platform=='macos':
        if platform.system()!='Darwin':raise ValueError('Build macOS installers on macOS')
        if not args.qemu or not args.qemu_source:raise ValueError('macOS requires --qemu and --qemu-source')
        command=[sys.executable,ROOT/'packaging/macos/build.py','--version',version,'--build-number',str(args.build_number),
                 '--qemu',args.qemu.resolve(),'--qemu-source',args.qemu_source.resolve(),'--output',destination]
        if args.dry_run:
            command+=['--adhoc']
            if not env.get('SPARKLE_PUBLIC_KEY'):
                generator=work/'test-key.swift'
                generator.write_text('import Foundation\nimport CryptoKit\nlet key=Curve25519.Signing.PrivateKey()\nlet folder=URL(fileURLWithPath:CommandLine.arguments[1])\nlet privateURL=folder.appendingPathComponent("test-private-key")\ntry key.rawRepresentation.base64EncodedString().write(to:privateURL,atomically:true,encoding:.utf8)\ntry FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:privateURL.path)\ntry key.publicKey.rawRepresentation.base64EncodedString().write(to:folder.appendingPathComponent("test-public-key"),atomically:true,encoding:.utf8)\n')
                run('swiftc',generator,'-o',work/'test-key',env=env)
                run(work/'test-key',work,env=env)
                env['SPARKLE_PUBLIC_KEY']=(work/'test-public-key').read_text().strip()
                env['SPARKLE_KEY_FILE']=str(work/'test-private-key')
        run(*command,env=env,cwd=ROOT)
    elif args.platform=='android':
        names=['MSM5XXX_ANDROID_KEYSTORE','MSM5XXX_ANDROID_KEY_ALIAS','MSM5XXX_ANDROID_STORE_PASSWORD','MSM5XXX_ANDROID_KEY_PASSWORD']
        if not all(env.get(name) for name in names):raise ValueError('Set Android release signing environment: '+', '.join(names))
        # Frozen third-party dependencies are build inputs, not a second application update path.
        run(sys.executable,ROOT/'android/runtime_cache.py','verify',env=env,cwd=ROOT)
        run('sh',ROOT/'android/prepare_runtime.sh','--source-only',env=env,cwd=ROOT)
        command=[args.gradle,'--no-daemon','--max-workers=2','-Pkotlin.compiler.execution.strategy=in-process',
                 '-PreleaseVersion='+version,'-PreleaseVersionCode='+str(args.build_number)]
        variant='Release'
        command+=[':app:assemble'+variant]
        run(*command,env=env,cwd=ROOT/'android')
        name='release/app-release.apk'
        apk=ROOT/'android/app/build/outputs/apk'/name
        if not apk.is_file():raise RuntimeError('Signed APK missing; configure the release signing environment')
        shutil.copy2(apk,destination/f'MSM5xxx-{version}-android-arm64.apk')
        run('bash',ROOT/'android/build_runtime_sources.sh',destination,env=env,cwd=ROOT)
    manifest(destination,version,commit,args.platform,args.dry_run)
    print(f'RELEASE OK {args.platform} {version} {commit}')



def powershell_quote(value):
    return "'"+str(value).replace("'","''")+"'"


def collect(wrapper,remote,destination):
    destination.mkdir(parents=True,exist_ok=True)
    run(wrapper,'pull',remote+'/release.json',destination/'release.json')
    metadata=json.loads((destination/'release.json').read_text())
    for entry in metadata['files']:
        name=entry['name']
        if Path(name).name!=name or '/' in name or '\\' in name:raise ValueError('Unsafe artifact name')
        run(wrapper,'pull',remote+'/'+name,destination/name)
        if digest(destination/name)!=entry['sha256']:raise RuntimeError('Transferred artifact checksum mismatch: '+name)
    run(wrapper,'pull',remote+'/SHA256SUMS',destination/'SHA256SUMS')


def build_all(args):
    version=release_version(args.tag);commit=source(args.tag)
    if platform.system()!='Linux':raise ValueError('Run the all-platform coordinator on Linux with the win and mac tools installed')
    for name in ['windows_work','macos_work','runtime','macos_qemu','macos_qemu_source','qemu','qemu_source']:
        if not getattr(args,name):raise ValueError('All-platform builds require --'+name.replace('_','-'))
    if not re.match(r'^[A-Za-z]:[\\/]',args.windows_work) or not args.macos_work.startswith('/'):
        raise ValueError('Remote workspace paths must be absolute')
    destination=args.output.resolve();destination.mkdir(parents=True,exist_ok=True)
    transfer=destination/'.work';transfer.mkdir(exist_ok=True)
    bundle=transfer/'release.bundle'
    run('git','bundle','create',bundle,'refs/tags/'+args.tag,'HEAD',cwd=ROOT)
    suffix=['--dry-run'] if args.dry_run else []
    for target in ['linux','android']:
        command=[sys.executable,Path(__file__).resolve(),'--tag',args.tag,'--platform',target,
                 '--output',destination/target,'--build-number',str(args.build_number),*suffix]
        if target=='linux':command+=['--qemu',args.qemu.resolve()]
        else:command+=['--gradle',args.gradle]
        run(*command,cwd=ROOT)
    winroot=args.windows_work.replace('\\','/')
    macroot=args.macos_work.rstrip('/')
    for wrapper,remote in [('win',winroot),('mac',macroot)]:run(wrapper,'push',bundle,remote+'/release.bundle')
    winout=winroot+'/release-output/'+version+'/windows'
    q=powershell_quote
    windows=f"""$ErrorActionPreference='Continue'; $work={q(winroot)}; $repo=Join-Path $work 'release-source';
$env:TMPDIR=Join-Path $work 'tmp';$env:TEMP=$env:TMPDIR;$env:TMP=$env:TMPDIR;New-Item -ItemType Directory -Force $env:TMPDIR | Out-Null;
$env:PATH=$env:PATH+';C:\\msys64\\usr\\bin'; $git=(Get-Command git -ErrorAction Stop).Source;
if (!(Test-Path (Join-Path $repo '.git'))) {{ & $git clone (Join-Path $work 'release.bundle') $repo; if($LASTEXITCODE -ne 0){{throw 'Source clone failed'}} }};
& $git -C $repo fetch (Join-Path $work 'release.bundle') --tags; if($LASTEXITCODE -ne 0){{throw 'Tag fetch failed'}};
& $git -C $repo checkout --detach {q(args.tag)}; if($LASTEXITCODE -ne 0){{throw 'Tag checkout failed'}};
if(Test-Path (Join-Path $work 'tools/dotnet/dotnet.exe')){{$env:DOTNET_ROOT=Join-Path $work 'tools/dotnet';$env:PATH=$env:DOTNET_ROOT+';'+$env:PATH}};
$env:DOTNET_CLI_HOME=Join-Path $work 'tools';$env:NUGET_PACKAGES=Join-Path $work 'tools/nuget';
Set-Location $repo; & python packaging/release.py --tag {q(args.tag)} --platform windows --output {q(winout)} --runtime {q(args.runtime)} {('--previous '+q(args.previous)) if args.previous else ''} {'--dry-run' if args.dry_run else ''}; exit $LASTEXITCODE"""
    run('win','run',windows)
    collect('win',winout,destination/'windows')
    macout=macroot+'/release-output/'+version+'/macos'
    m=shlex.quote
    mac=f"""set -e; cd {m(macroot)}; export TMPDIR="$PWD/tmp"; mkdir -p "$TMPDIR"; if [ ! -d release-source/.git ]; then git clone release.bundle release-source; fi;
git -C release-source fetch "$PWD/release.bundle" --tags; git -C release-source checkout --detach {m(args.tag)};
cd release-source; python3 packaging/release.py --tag {m(args.tag)} --platform macos --output {m(macout)} --qemu {m(args.macos_qemu)} --qemu-source {m(args.macos_qemu_source)} --build-number {args.build_number} {'--dry-run' if args.dry_run else ''}"""
    run('mac','run',mac)
    collect('mac',macout,destination/'macos')
    source_archive=destination/f'MSM5xxx-{version}-source.tar.gz'
    run('git','archive','--format=tar.gz','--prefix=msm5xxx-'+version+'/',
        '--output='+str(source_archive),args.tag,cwd=ROOT)
    qemu_source=args.qemu_source.resolve()
    if not (qemu_source/'COPYING').is_file():raise ValueError('--qemu-source must identify the staged QEMU source tree')
    run('tar','--exclude=*/.git','--exclude=*.bin','--exclude=*.rom','--exclude=*.img','--exclude=*.fd',
        '--exclude=*.pyc','--exclude=*/__pycache__','-cJf',destination/'MSM5xxx-QEMU-corresponding-source.tar.xz',
        '-C',qemu_source.parent,qemu_source.name)
    records={target:json.loads((destination/target/'release.json').read_text()) for target in ['windows','linux','android','macos']}
    if any(item['version']!=version or item['commit']!=commit for item in records.values()):
        raise RuntimeError('Platform artifacts do not identify the same tag commit')
    (destination/'release.json').write_text(json.dumps({'tag':args.tag,'commit':commit,'dry_run':args.dry_run,'platforms':records},indent=2)+'\n')
    sums=[f'{digest(path)}  {path.name}\n' for path in [source_archive,destination/'MSM5xxx-QEMU-corresponding-source.tar.xz']]
    for target,record in records.items():
        sums.extend(f"{entry['sha256']}  {target}/{entry['name']}\n" for entry in record['files'])
    (destination/'SHA256SUMS').write_text(''.join(sums))
    print('ALL INSTALLERS OK '+args.tag+' '+commit)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag',required=True)
    parser.add_argument('--platform',required=True,choices=['all','windows','linux','macos','android'])
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--dry-run',action='store_true',help='Create unnotarized macOS test artifacts; never publish them')
    parser.add_argument('--runtime',type=Path,help='Complete Windows QEMU runtime directory')
    parser.add_argument('--qemu',type=Path);parser.add_argument('--qemu-source',type=Path)
    parser.add_argument('--previous',type=Path,help='Previous Windows release directory for Velopack delta generation')
    parser.add_argument('--build-number',type=int)
    parser.add_argument('--gradle',default='gradle')
    parser.add_argument('--windows-work');parser.add_argument('--macos-work')
    parser.add_argument('--macos-qemu');parser.add_argument('--macos-qemu-source')
    args=parser.parse_args()
    if args.build_number is None:
        version=release_version(args.tag)
        major,minor,patch=map(int,version.split('-',1)[0].split('.'))
        # shortcut: one default RC per version; pass increasing build numbers for additional candidates.
        args.build_number=major*1000000+minor*10000+patch*100+(0 if '-' in version else 1)
    if not 1<=args.build_number<=2100000000:parser.error('--build-number must be positive, increase, and fit Android versionCode')
    try:
        if args.platform=='all':build_all(args)
        else:build(args)
    except (ValueError,RuntimeError) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
