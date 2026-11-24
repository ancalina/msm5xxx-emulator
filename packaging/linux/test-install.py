#!/usr/bin/env python3
"""Native Linux lifecycle test in an isolated X11/D-Bus session and dpkg root."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

APP='io.github.ancalina.MSM5xxx'

def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args],check=True,**kwargs)

def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def wait_for(condition, seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=condition()
        if result: return result
        time.sleep(.5)
    raise RuntimeError('Timed out waiting for native UI or package state')

def window():
    result=subprocess.run(['xdotool','search','--onlyvisible','--name','Firmware Library'],capture_output=True,text=True)
    return result.stdout.splitlines()[0] if result.returncode==0 else None

def key(*keys): run('xdotool','key',*keys)

def click(win,x,y): run('xdotool','mousemove','--window',win,str(x),str(y),'click','1')

def capture(work,name):
    time.sleep(1)
    run('import','-window',window(),work/(name+'.png'))

def quit_app():
    run('gdbus','call','--session','--dest',APP,'--object-path','/io/github/ancalina/MSM5xxx',
        '--method','org.gtk.Actions.Activate','quit','[]','{}',stdout=subprocess.DEVNULL)
    wait_for(lambda:not window(),30)

def launch(command,work,name,env):
    log=(work/(name+'.log')).open('w')
    process=subprocess.Popen([str(command)],env=env,stdout=log,stderr=subprocess.STDOUT)
    win=wait_for(window)
    run('xdotool','windowfocus',win)
    time.sleep(2)
    return process,win

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('baseline_image',type=Path);parser.add_argument('release_image',type=Path)
    parser.add_argument('baseline_deb',type=Path);parser.add_argument('release_deb',type=Path)
    parser.add_argument('work',type=Path)
    args=parser.parse_args();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    results=[]
    def require(value,label):
        if not value: raise AssertionError(label)
        results.append(label);(work/'results.json').write_text(json.dumps(results,indent=2))
    try:
        release=args.release_image.resolve(); expected=digest(release)
        feed=work/'release.json'
        feed.write_text(json.dumps({'tag_name':'v0.2.0-rc','prerelease':True,
            'html_url':'https://github.com/ancalina/msm5xxx-emulator/releases/tag/v0.2.0-rc',
            'assets':[{'name':release.name,'browser_download_url':release.as_uri(),
                       'digest':'sha256:'+expected,'size':release.stat().st_size}]}))
        env=dict(os.environ,MSM5XXX_UPDATE_FEED=str(feed))
        image=work/'MSM5xxx Test.AppImage';shutil.copy2(args.baseline_image,image);image.chmod(0o755)
        baseline_hash=digest(image)
        process,win=launch(image,work,'appimage-baseline',env)
        original_pid=subprocess.check_output(['xdotool','getwindowpid',win],text=True).strip()
        data=Path(env['XDG_DATA_HOME']);state=data/'msm5xxx';state.mkdir(parents=True,exist_ok=True)
        saved=state/'retention-test';saved.write_bytes(b'library settings and saved state')
        entry=data/'applications'/f'{APP}.desktop'
        require(entry.is_file(),'AppImage registers application menu entry')
        require((data/'icons/hicolor/256x256/apps'/f'{APP}.png').is_file(),'AppImage registers icon')
        capture(work,'appimage-first-run')
        key('ctrl+comma');time.sleep(1)
        capture(work,'appimage-updates')
        click(win,470,162)
        config=state/'last_config.json'
        wait_for(lambda:config.exists() and json.loads(config.read_text()).get('check_updates_on_start') is False)
        time.sleep(1)  # Let the stock switch animation finish before toggling again.
        click(win,470,162)
        wait_for(lambda:json.loads(config.read_text()).get('check_updates_on_start') is True)
        saved_settings=digest(config)
        click(win,420,214);time.sleep(1)
        capture(work,'appimage-update-review')
        # The stock AlertDialog stacks responses at this constrained window width.
        click(win,280,372)
        wait_for(lambda:digest(image)==expected,120)
        try:
            wait_for(lambda:window() and subprocess.check_output(['xdotool','getwindowpid',window()],text=True).strip()!=original_pid,60)
        except Exception:
            (work/'processes.txt').write_text(subprocess.check_output(['ps','-eo','pid,ppid,stat,args'],text=True))
            run('import','-window','root',work/'restart-failure.png')
            raise
        require(digest(image.with_name(image.name+'.old'))==baseline_hash,'AppImage keeps previous version')
        require(digest(config)==saved_settings and saved.read_bytes()==b'library settings and saved state','AppImage update preserves user data')
        capture(work,'appimage-updated')
        key('ctrl+comma');capture(work,'appimage-updated-version');key('Escape')
        quit_app()
        image.unlink();image.with_name(image.name+'.old').unlink()
        entry.unlink();(data/'icons/hicolor/256x256/apps'/f'{APP}.png').unlink()
        require(saved.exists(),'AppImage removal preserves user data')
        # A separate dpkg database records the host libc actually used by the rooted install.
        root=work/'deb-root';db=work/'dpkg';root.mkdir();db.mkdir()
        status=subprocess.check_output(['dpkg-query','-s','libc6:amd64'],text=True)
        (db/'status').write_text(status+'\n')
        def dpkg(*arguments):
            run('fakeroot','dpkg','--force-not-root','--log='+str(work/'dpkg-actions.log'),'--root='+str(root),'--admindir='+str(db),*arguments,
                stdout=(work/'dpkg.log').open('a'),stderr=subprocess.STDOUT,
                env=dict(os.environ,FAKEROOTDONTTRYCHOWN='1'))
        dpkg('--install',args.baseline_deb.resolve())
        require((root/'usr/share/applications'/f'{APP}.desktop').exists(),'Debian install registers menu entry')
        deb_env=dict(env,PATH=str(root/'usr/bin')+':'+env['PATH'],XDG_DATA_DIRS=str(root/'usr/share')+':/usr/local/share:/usr/share')
        deb_env.pop('APPIMAGE',None)
        process,win=launch(root/'usr/bin/msm5xxx-desktop',work,'deb-baseline',deb_env)
        key('ctrl+comma');time.sleep(1);click(win,420,214);capture(work,'deb-update-notice');key('Escape');key('Escape')
        quit_app();dpkg('--install',args.release_deb.resolve())
        process,win=launch(root/'usr/bin/msm5xxx-desktop',work,'deb-updated',deb_env)
        key('ctrl+comma');capture(work,'deb-updated-version');key('Escape');quit_app()
        require(digest(config)==saved_settings and saved.exists(),'Debian upgrade preserves user data')
        dpkg('--remove','msm5xxx-emulator')
        require(not (root/'usr/bin/msm5xxx-desktop').exists(),'Debian uninstall removes application')
        require(not (root/'usr/share/applications'/f'{APP}.desktop').exists(),'Debian uninstall removes menu entry')
        require(saved.exists(),'Debian uninstall preserves user data')
        (work/'result.txt').write_text('PASS\n')
    except Exception:
        import traceback
        (work/'error.txt').write_text(traceback.format_exc());(work/'result.txt').write_text('FAIL\n')
        raise


if __name__=='__main__':main()
