"""Configure bundled image loaders and register AppImages in the user application menu."""
import os
from pathlib import Path
import shutil
import tempfile


def quoted(path: str) -> str:
    if '\n' in path or '\r' in path:
        raise ValueError('An application path cannot contain a newline')
    path = path.replace('%', '%%')
    for character in ('\\', '"', '`', '$'):
        path = path.replace(character, '\\' + character)
    return '"' + path.replace('\\', '\\\\') + '"'


def main():
    image = Path(os.environ['APPIMAGE']).resolve(strict=True)
    bundle = Path(os.environ['MSM5XXX_BUNDLE'])
    data = Path(os.environ.get('XDG_DATA_HOME', Path.home()/'.local/share'))
    application = data/'applications/io.github.ancalina.MSM5xxx.desktop'
    icon = data/'icons/hicolor/256x256/apps/io.github.ancalina.MSM5xxx.png'
    application.parent.mkdir(parents=True, exist_ok=True)
    icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle/'share/icons/hicolor/256x256/apps/io.github.ancalina.MSM5xxx.png', icon)
    text = (bundle/'share/applications/io.github.ancalina.MSM5xxx.desktop').read_text()
    text = text.replace('Exec=msm5xxx-desktop %F', 'Exec=/usr/bin/env '+quoted(str(image))+' %F\nTryExec='+str(image).replace('\\','\\\\'))
    text = text.replace('Icon=io.github.ancalina.MSM5xxx', 'Icon='+str(icon))
    temporary = application.with_suffix('.desktop.tmp')
    temporary.write_text(text)
    temporary.replace(application)


def loaders(bundle: Path, cache: Path) -> Path:
    data = Path(tempfile.mkdtemp(prefix='glycin-', dir=cache))
    source = bundle/'share/glycin-loaders'
    destination = data/'glycin-loaders'
    shutil.copytree(source,destination)
    for config in destination.rglob('*.conf'):
        text=config.read_text()
        text=text.replace('Exec=/usr/libexec/', 'Exec='+str(bundle/'libexec').replace('\\','\\\\')+'/')
        config.write_text(text)
    return data


if __name__ == '__main__':
    if os.environ.get('APPIMAGE'):
        main()
    print(loaders(Path(os.environ['MSM5XXX_BUNDLE']),Path(os.environ['MSM5XXX_RUNTIME_CACHE'])))
