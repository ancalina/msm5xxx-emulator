#!/usr/bin/env python3
"""Collect corresponding distribution sources for the libraries in a desktop bundle."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def formula_inputs(recipe):
    """Installed Homebrew recipes retain the exact upstream and patch checksums."""
    pairs = re.findall(r'(?m)^\s*url "(https://[^"\n]+)"[^\n]*\n(?:(?!\s*(?:url|sha256)\b).*\n)*?\s*sha256 "([a-f0-9]{64})"', recipe)
    if not pairs or '#{' in ''.join(url for url, _ in pairs):
        raise ValueError('Expected literal, checksummed source URLs in installed formula')
    return pairs


def macos(runtime, stage):
    cellar = Path(subprocess.check_output(['brew', '--cellar'], text=True).strip())
    for row in (runtime/'licenses/HOMEBREW_PACKAGES.txt').read_text().splitlines():
        name, version = row.split()
        prefix = cellar/name/version
        recipe = prefix/'.brew'/(name+'.rb')
        target = stage/name; target.mkdir()
        shutil.copy2(recipe, target/recipe.name)
        shutil.copy2(prefix/'INSTALL_RECEIPT.json', target/'INSTALL_RECEIPT.json')
        for index, (url, checksum) in enumerate(formula_inputs(recipe.read_text())):
            path = target/(str(index)+'-'+url.rsplit('/', 1)[1])
            with urlopen(url, timeout=120) as source, path.open('wb') as output:
                shutil.copyfileobj(source, output)
            with path.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
            if actual != checksum:
                raise ValueError('Source checksum mismatch: '+path.name)


def linux(runtime, stage, work):
    # shortcut: the Linux build uses Ubuntu/Debian packages; add another source
    # package backend before building on a different distribution.
    apt = work/'apt'; (apt/'lists/partial').mkdir(parents=True, exist_ok=True)
    (apt/'cache').mkdir(exist_ok=True)
    sources=[]
    for path in Path('/etc/apt/sources.list.d').glob('*.sources'):
        data=path.read_text()
        if re.search(r'^URIs:.*(?:ubuntu.com|debian.org)', data, re.M):
            sources.append(re.sub(r'^Types:.*$', 'Types: deb-src', data, flags=re.M))
    if not sources: raise RuntimeError('No Ubuntu/Debian source repositories found')
    source_list=apt/'sources.sources'; source_list.write_text('\n\n'.join(sources))
    options=['-o','Dir::Etc::sourcelist='+str(source_list), '-o','Dir::Etc::sourceparts=-',
             '-o','Dir::State::lists='+str(apt/'lists'), '-o','Dir::Cache='+str(apt/'cache'),
             '-o','APT::Get::List-Cleanup=0',
             '-o','APT::Sandbox::User='+os.environ.get('USER','root')]
    run('apt-get',*options,'update')
    packages={}
    for row in (runtime/'PACKAGES.txt').read_text().splitlines():
        name, version=row.split()
        installed=subprocess.check_output(['dpkg-query','-W','-f=${Version}\t${source:Package}\t${source:Version}',name],text=True)
        actual, source, revision=installed.split('\t')
        if actual != version: raise RuntimeError('Installed package changed since bundling: '+name)
        packages[name]={'version':version,'source':source,'source_version':revision}
    (stage/'PACKAGES.json').write_text(json.dumps(packages,indent=2)+'\n')
    for source, revision in sorted({(p['source'],p['source_version']) for p in packages.values()}):
        run('apt-get',*options,'source','--download-only','--only-source',source+'='+revision,cwd=stage)


def cached_linux_sources(runtime, stage):
    packages=stage/'PACKAGES.json';checksums=stage/'SHA256SUMS'
    if not packages.is_file() or not checksums.is_file():return False
    expected=dict(row.split() for row in (runtime/'PACKAGES.txt').read_text().splitlines())
    cached=json.loads(packages.read_text())
    if expected!={name:record['version'] for name,record in cached.items()}:return False
    recorded=set()
    for row in checksums.read_text().splitlines():
        checksum,name=row.split(maxsplit=1)
        path=stage/name
        if path.is_symlink() or not path.resolve().is_relative_to(stage.resolve()):
            raise ValueError('Unsafe cached source path')
        with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=checksum:raise ValueError('Cached source checksum mismatch: '+name)
        recorded.add(name)
    actual={str(path.relative_to(stage)) for path in stage.rglob('*') if path.is_file() and path!=checksums}
    if actual!=recorded:raise ValueError('Cached source manifest does not cover every file')
    return True


def collect(target, runtime, output):
    stage=output/'.work/runtime-sources'
    cached=target=='linux' and cached_linux_sources(runtime,stage)
    if not cached:
        if stage.exists(): shutil.rmtree(stage)
        stage.mkdir(parents=True)
        if target=='macos': macos(runtime,stage)
        elif target=='linux': linux(runtime,stage,output/'.work')
        else: raise ValueError('Unsupported source distribution')
    (stage/'README.txt').write_text('Corresponding upstream sources, distribution patches and build recipes for the bundled libraries. QEMU and project sources are supplied separately. Rebuild distribution packages using the included recipes.\n')
    sums=[]
    for path in sorted(stage.rglob('*')):
        if path.is_file() and path!=stage/'SHA256SUMS':
            with path.open('rb') as stream: checksum=hashlib.file_digest(stream,'sha256').hexdigest()
            sums.append(checksum+'  '+str(path.relative_to(stage))+'\n')
    (stage/'SHA256SUMS').write_text(''.join(sums))
    archive=output/f'MSM5xxx-QEMU-{target}-runtime-sources.tar.xz'
    with tarfile.open(archive,'w:xz') as tar: tar.add(stage,arcname=target+'-runtime-sources')
    return archive
