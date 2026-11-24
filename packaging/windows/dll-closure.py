"""Copy the recursively imported MinGW DLLs; reject unresolved imports."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

target = Path(sys.argv[1])
available = {p.name.casefold(): p for p in (Path(sys.prefix) / 'bin').glob('*.dll')}
pending = [target / 'qemu-system-arm.exe']
copied = set()
system = Path(os.environ['SystemRoot']) / 'System32'
while pending:
    binary = pending.pop()
    imports = subprocess.check_output(['objdump', '-p', str(binary)], text=True)
    for name in re.findall(r'^\s*DLL Name:\s*(\S+)', imports, re.M):
        key = name.casefold()
        source = available.get(key)
        if source is None:
            if key.startswith(('api-ms-win-', 'ext-ms-win-')) or (system / name).is_file():
                continue
            raise SystemExit(f'unresolved DLL: {name} in {binary.name}')
        if key not in copied:
            destination = target / source.name
            shutil.copy2(source, destination)
            copied.add(key)
            pending.append(destination)
(target.parent / 'DLLS.txt').write_bytes(('\n'.join(sorted(copied)) + '\n').encode('utf-8'))
