import argparse,base64,hashlib,json,os,subprocess,time,xml.etree.ElementTree as ET
from pathlib import Path
parser=argparse.ArgumentParser(description="Real Android update lifecycle for the isolated debug app")
parser.add_argument('--device',required=True);parser.add_argument('--artifacts',required=True,type=Path)
parser.add_argument('--work',required=True,type=Path);parser.add_argument('--adb',default='adb')
args=parser.parse_args()
WORK=args.work.resolve();WORK.mkdir(parents=True,exist_ok=True)
DEVICE=args.device;PACKAGE='org.msm5xxx.emulator.debug'
def adb(*arguments,**kw):return subprocess.run([args.adb,'-s',DEVICE,*arguments],check=True,**kw)
def shell(command):return adb('shell',command,stdout=subprocess.PIPE,text=True).stdout
def wait(test,seconds=180):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=test()
  if value is not None and value is not False:return value
  time.sleep(1)
 raise RuntimeError('Timed out: '+test.__name__)
def dump():
 shell('input keyevent KEYCODE_WAKEUP');shell('wm dismiss-keyguard')
 try:
  result=shell('uiautomator dump /data/local/tmp/msm5xxx-installers-ui.xml')
  if 'dumped to:' not in result:return None
  output=shell('cat /data/local/tmp/msm5xxx-installers-ui.xml')
 except subprocess.CalledProcessError:return None
 start=output.find('<?xml');end=output.rfind('</hierarchy>')
 if start<0:return None
 return ET.fromstring(output[start:end+12])
def node(text):
 tree=dump()
 if tree is None:return None
 return next((n for n in tree.iter('node') if n.get('text')==text or n.get('content-desc')==text),None)
def tap(text):
 shell('input keyevent KEYCODE_WAKEUP')
 n=wait(lambda:node(text));import re
 x1,y1,x2,y2=map(int,re.findall(r'\d+',n.get('bounds')))
 shell(f'input tap {(x1+x2)//2} {(y1+y2)//2}');time.sleep(1)
def shot(name):
 adb('exec-out','screencap','-p',stdout=(WORK/(name+'.png')).open('wb'))
def write(name,data):
 # Windows adb treats control-Z as EOF on stdin; transfer ASCII and decode on-device.
 adb('shell','-T',f"run-as {PACKAGE} sh -c 'base64 -d > {name}'",input=base64.b64encode(data),stdout=subprocess.DEVNULL)
def launch():
 shell('input keyevent KEYCODE_WAKEUP');shell('wm dismiss-keyguard');shell('cmd statusbar collapse')
 shell('am force-stop '+PACKAGE)
 shell('am start -n '+PACKAGE+'/org.msm5xxx.emulator.FullIcon')
 time.sleep(3)

def main():
 baseline=args.artifacts/'MSM5xxx-0.1.99-android-arm64.apk'
 release=args.artifacts/'MSM5xxx-0.2.0-rc-android-arm64.apk'
 adb('install','-r','-d',str(baseline),stdout=(WORK/'install.log').open('w'),stderr=subprocess.STDOUT)
 shell('input keyevent KEYCODE_WAKEUP')
 shell('am force-stop '+PACKAGE);time.sleep(1)
 shell(f'appops set {PACKAGE} REQUEST_INSTALL_PACKAGES deny')
 shell(f'run-as {PACKAGE} mkdir -p files shared_prefs')
 write('shared_prefs/launcher.xml',b'<map><string name="ui_language">en</string><boolean name="check_updates" value="true"/></map>')
 write('files/installer-test-retention',b'keep library settings state')
 shell(f'run-as {PACKAGE} rm -f files/update-release.json files/update.apk')
 print('Checking baseline first-run UI',flush=True)
 launch();wait(lambda:node('Settings'));shot('first-run')
 feed={'tag_name':'v0.2.0-rc','prerelease':True,'assets':[{'name':release.name,'browser_download_url':f'file:/data/user/0/{PACKAGE}/files/update.apk','size':release.stat().st_size,'digest':'sha256:'+hashlib.sha256(release.read_bytes()).hexdigest()}]}
 write('files/update-release.json',json.dumps(feed).encode())
 write('files/update.apk',release.read_bytes()[:-1])
 print('Checking update offer',flush=True)
 launch();wait(lambda:node('Update available'));shot('update-ready')
 tap('Download and install')
 # The system permission screen is exercised before allowing this test package.
 time.sleep(2);shot('install-permission')
 shell(f'appops set {PACKAGE} REQUEST_INSTALL_PACKAGES allow')
 shell('input keyevent KEYCODE_BACK');time.sleep(1)
 tap('Download and install');wait(lambda:node('Could not check or download the update. Please try again.'))
 shot('corrupt-apk-rejected');tap('OK')
 print('Installing verified APK',flush=True)
 write('files/update.apk',release.read_bytes())
 launch();tap('Download and install')
 def confirmation():
  tree=dump()
  if tree is None:return None
  for item in tree.iter('node'):
   if item.get('text','').casefold() in ['update','install','업데이트','설치']:
    return tree,item
  return None
 tree,button=wait(confirmation)
 (WORK/'installer.xml').write_text(ET.tostring(tree,encoding='unicode'))
 shot('system-installer')
 import re
 left,top,right,bottom=map(int,re.findall(r'\d+',button.get('bounds')))
 shell(f'input tap {(left+right)//2} {(top+bottom)//2}')
 wait(lambda:'versionName=0.2.0-rc' in shell('dumpsys package '+PACKAGE),600)
 assert shell(f'run-as {PACKAGE} cat files/installer-test-retention').strip()=='keep library settings state'
 launch();wait(lambda:node('Settings'));shot('updated')
 tap('Settings');shell('input swipe 350 1250 350 450 500');time.sleep(2);shot('settings-updates')
 (WORK/'settings.xml').write_text(ET.tostring(dump(),encoding='unicode'))
 # The stock switch is at the trailing edge of its settings row.
 import re
 row=wait(lambda:node('Check for updates on start'))
 _,top,_,bottom=map(int,re.findall(r'\d+',row.get('bounds')))
 shell(f'input tap 650 {(top+bottom)//2}')
 wait(lambda:'name="check_updates" value="false"' in shell(f'run-as {PACKAGE} cat shared_prefs/launcher.xml'))
 shell(f'input tap 650 {(top+bottom)//2}')
 wait(lambda:'name="check_updates" value="true"' in shell(f'run-as {PACKAGE} cat shared_prefs/launcher.xml'))
 tap('Check for updates');wait(lambda:node('You have the latest version.'));shot('manual-check-current')
 # Remove only this test's files; leave its installed candidate available for review.
 shell(f'run-as {PACKAGE} rm files/update-release.json files/update.apk files/installer-test-retention')
 shell('rm /data/local/tmp/msm5xxx-installers-ui.xml')
 (WORK/'result.txt').write_text('PASS\n')
if __name__=='__main__':
 try:main()
 except Exception:
  import traceback
  (WORK/'error.txt').write_text(traceback.format_exc());raise
