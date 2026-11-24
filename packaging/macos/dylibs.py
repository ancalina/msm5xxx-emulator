#!/usr/bin/env python3
"""Bundle non-system absolute Mach-O dependencies and relocate their load commands."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys


def bundle(executable, destination):
    executable, destination = Path(executable).resolve(), Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    pending = [executable]
    copied = {}
    origins = {}
    while pending:
        binary = pending.pop()
        dependencies = subprocess.check_output(['otool','-L',str(binary)],text=True).splitlines()[1:]
        for line in dependencies:
            name = line.strip().split(' (',1)[0]
            if not name.startswith('/') or name.startswith(('/usr/lib/','/System/')):
                continue
            source = Path(name).resolve()
            target = destination/source.name
            fingerprint = hashlib.sha256(source.read_bytes()).hexdigest()
            if source.name in copied and copied[source.name] != fingerprint:
                raise RuntimeError('Conflicting dependency: '+source.name)
            if source.name not in copied:
                copied[source.name] = fingerprint
                origins[source.name] = source
                shutil.copy2(source,target); target.chmod(0o755)
                subprocess.run(['install_name_tool','-id','@rpath/'+target.name,str(target)],check=True)
                pending.append(target)
            relative = '@executable_path/../lib/' if binary == executable else '@loader_path/'
            subprocess.run(['install_name_tool','-change',name,relative+target.name,str(binary)],check=True)
    return origins

if __name__ == '__main__': bundle(*sys.argv[1:])
