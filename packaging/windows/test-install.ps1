param(
    [Parameter(Mandatory=$true)][string]$BaselineSetup,
    [Parameter(Mandatory=$true)][string]$Feed,
    [Parameter(Mandatory=$true)][string]$WorkDirectory
)
# Run in an interactive desktop. Use the real default install location and isolated test data.
$ErrorActionPreference='Stop'
if (Test-Path $WorkDirectory) { throw 'Test work directory must not exist.' }
New-Item -ItemType Directory $WorkDirectory | Out-Null
$work=(Resolve-Path $WorkDirectory).Path
$install=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MSM5xxx.Desktop'
if (Test-Path $install) { throw 'Default test install location must not exist.' }
$productionData=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MSM5xxx'
if ($productionData.StartsWith($install+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or $productionData -eq $install) { throw 'Production user data must be outside the install tree.' }
New-Item -ItemType Directory "$work/tmp" | Out-Null
$env:TEMP="$work/tmp"; $env:TMP=$env:TEMP; $env:TMPDIR=$env:TEMP
$env:MSM5XXX_STATE_DIR="$work/state"
$env:MSM5XXX_BUNDLE=$null; $env:MSM5XXX_PYTHON=$null; $env:MSM5XXX_QEMU=$null
$releaseFeed=(Resolve-Path $Feed).Path
$env:MSM5XXX_UPDATE_FEED="$work/feed"
New-Item -ItemType Directory $env:MSM5XXX_UPDATE_FEED | Out-Null
Copy-Item "$releaseFeed/releases.win.json" $env:MSM5XXX_UPDATE_FEED
Copy-Item "$releaseFeed/*-delta.nupkg" $env:MSM5XXX_UPDATE_FEED
# Omit the new full package: success proves the delta was used without fallback.
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class InstallerTestWindow {
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern void keybd_event(byte key,byte scan,uint flags,UIntPtr extra);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("dwmapi.dll")] public static extern int DwmFlush();
 private delegate bool EnumProc(IntPtr h,IntPtr p);
 [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc f,IntPtr p);
 [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr h,EnumProc f,IntPtr p);
 [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr h,System.Text.StringBuilder text,int size);
 [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr h,uint message,IntPtr w,IntPtr l);
 public static void DismissCompletion(int process) {
  EnumWindows((h,p)=> { uint id; GetWindowThreadProcessId(h,out id); if(id==process) {
   EnumChildWindows(h,(button,arg)=> { var cls=new System.Text.StringBuilder(64); GetClassName(button,cls,64); var control=GetDlgCtrlID(button);
    if(cls.ToString()=="Button" && (control==0 || control==1)) PostMessage(h,0x111,new IntPtr(control),button); return true;
   },IntPtr.Zero);
  } return true; },IntPtr.Zero);
 }
}
'@
function Require($condition,[string]$message) { if (!$condition) { throw $message }; $message | Add-Content "$work/results.txt" }
function WaitFor([scriptblock]$condition,[int]$seconds=180) {
 $deadline=(Get-Date).AddSeconds($seconds)
 do { $result=& $condition; if ($result) { return $result }; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline)
 throw "Timed out: $condition"
}
function Elements {
 foreach ($process in @(Get-Process MSM5xxx.Desktop -ErrorAction SilentlyContinue | Where-Object {$_.Path -like "$install*"})) {
  $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$process.Id)
  try {
   $windows=[System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children,$condition)
   foreach ($window in $windows) { $window; $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition) }
  } catch { $_.Exception.Message | Add-Content "$work/automation-retries.txt" }
 }
}
function ById([string]$id) { Elements | Where-Object {$_.Current.AutomationId -eq $id -and !$_.Current.IsOffscreen -and $_.Current.IsEnabled} | Select-Object -First 1 }
function Invoke($element) { $element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Toggle($element) { $element.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Toggle() }
function WindowFor([string]$id) {
 $element=Elements | Where-Object {$_.Current.AutomationId -eq $id} | Select-Object -First 1
 while ($element) {
  if ($element.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window -and $element.Current.NativeWindowHandle) { return $element }
  $element=[System.Windows.Automation.TreeWalker]::RawViewWalker.GetParent($element)
 }
 throw "Window missing for control: $id"
}
function Capture([string]$name,[string]$title='main') {
 $elements=@(Elements)
 $elements | ForEach-Object { try { [pscustomobject]@{name=$_.Current.Name; id=$_.Current.AutomationId; type=$_.Current.ControlType.ProgrammaticName} } catch {} } | ConvertTo-Json | Set-Content "$work/$name.json"
 $window=WindowFor $(if ($title -eq 'settings') { 'updates-check' } else { 'app-menu' })
 [InstallerTestWindow]::keybd_event(0x12,0,0,[UIntPtr]::Zero)
 [InstallerTestWindow]::SetForegroundWindow([IntPtr]$window.Current.NativeWindowHandle) | Out-Null
 [InstallerTestWindow]::keybd_event(0x12,0,2,[UIntPtr]::Zero)
 Start-Sleep -Seconds 2
 [InstallerTestWindow]::DwmFlush() | Out-Null
 $rect=$window.Current.BoundingRectangle
 $image=New-Object System.Drawing.Bitmap([int]$rect.Width,[int]$rect.Height)
 $graphics=[System.Drawing.Graphics]::FromImage($image)
 $dc=$graphics.GetHdc()
 try { if (![InstallerTestWindow]::PrintWindow([IntPtr]$window.Current.NativeWindowHandle,$dc,2)) { throw 'Window capture failed' } }
 finally { $graphics.ReleaseHdc($dc) }
 $image.Save("$work/$name.png"); $graphics.Dispose(); $image.Dispose()
}
try {
 Start-Process (Resolve-Path $BaselineSetup).Path
 $desktop=WaitFor { ById 'install-desktop-shortcut' }
 Require ($desktop.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Current.ToggleState -eq 0) 'Desktop shortcut defaults off'
 $automatic=ById 'install-automatic'
 Require ($automatic.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern).Current.ToggleState -eq 1) 'Automatic checks default on'
 Capture 'first-run'
 Toggle $desktop; Toggle $automatic
 Invoke (ById 'PrimaryButton')
 WaitFor { Test-Path "$env:MSM5XXX_STATE_DIR/updates.json" } | Out-Null
 Require ((Get-Content "$env:MSM5XXX_STATE_DIR/updates.json" -Raw | ConvertFrom-Json).Automatic -eq $false) 'First-run options persist'
 $shortcut=Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'MSM5xxx Emulator.lnk'
 Require (Test-Path $shortcut) 'Optional desktop shortcut exists'
 $shell=New-Object -ComObject WScript.Shell
 $link=$shell.CreateShortcut($shortcut)
 Require (Test-Path $link.TargetPath) 'Desktop shortcut target exists'
 [Runtime.InteropServices.Marshal]::FinalReleaseComObject($link) | Out-Null
 [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
 Require (@(Get-ChildItem HKCU:/Software/Microsoft/Windows/CurrentVersion/Uninstall | Where-Object {(Get-ItemProperty $_.PSPath).DisplayName -eq 'MSM5xxx Emulator'}).Count -eq 1) 'Per-user uninstall entry exists'
 Require (Test-Path "$install/current/MSM5xxx.Desktop.exe") 'Default per-user install path is used'
 Require (Test-Path (Join-Path ([Environment]::GetFolderPath('Programs')) 'MSM5xxx Emulator.lnk')) 'Start menu shortcut exists'
 Set-Content "$env:MSM5XXX_STATE_DIR/retention-test.txt" 'preserve across update and uninstall'
 $settingsHash=(Get-FileHash "$env:MSM5XXX_STATE_DIR/updates.json").Hash
 Capture 'installed'
 Invoke (ById 'app-menu'); Invoke (WaitFor { ById 'settings-open' })
 $automatic=WaitFor { ById 'updates-automatic' }
 Toggle $automatic
 WaitFor { (Get-Content "$env:MSM5XXX_STATE_DIR/updates.json" -Raw | ConvertFrom-Json).Automatic } | Out-Null
 Toggle $automatic
 WaitFor { !(Get-Content "$env:MSM5XXX_STATE_DIR/updates.json" -Raw | ConvertFrom-Json).Automatic } | Out-Null
 Invoke (WaitFor { ById 'updates-check' })
 WaitFor { ById 'updates-restart' } | Out-Null
 Capture 'update-settings' 'settings'
 $settingsWindow=WindowFor 'updates-check'
 $settingsWindow.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
 Capture 'update-ready'
 try { Invoke (ById 'updates-restart') } catch { $_ | Out-String | Set-Content "$work/restart-automation.txt" }
 WaitFor { (Get-Item "$install/current/MSM5xxx.Desktop.dll" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion -like '0.2.0-rc*' } | Out-Null
 WaitFor { ById 'app-menu' } | Out-Null
 Require ((Get-FileHash "$env:MSM5XXX_STATE_DIR/updates.json").Hash -eq $settingsHash) 'Update preserves preferences'
 Require ((Get-Content "$env:MSM5XXX_STATE_DIR/retention-test.txt") -eq 'preserve across update and uninstall') 'Update preserves saved data'
 Capture 'updated'
 $window=WindowFor 'app-menu'
 $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
 WaitFor { !(Get-Process MSM5xxx.Desktop -ErrorAction SilentlyContinue | Where-Object {$_.Path -like "$install*"}) } | Out-Null
 $uninstall=Start-Process "$install/Update.exe" -ArgumentList 'uninstall' -PassThru
 # Confirm the updater's uninstall prompt, then choose No on the separate data prompt.
 function AnswerUninstall([bool]$deleteData) {
  $deadline=(Get-Date).AddSeconds(180)
  $confirmed=$false
  do {
   foreach ($process in @(Get-Process MSM5xxx.Desktop,Update -ErrorAction SilentlyContinue | Where-Object {$_.Path -like "$install*"})) {
    $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$process.Id)
    $windows=[System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children,$condition)
    foreach ($window in $windows) {
     $dataPrompt=@($window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition) | Where-Object {$_.Current.Name -like 'Delete your MSM5xxx library*'}).Count -gt 0
     if (!$dataPrompt -and ($process.ProcessName -ne 'Update' -or $process.Path -notlike "$install*" -or $confirmed)) { continue }
     $id=if ($dataPrompt -and !$deleteData) { '7' } else { '6' }
     $condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,$id)
     $button=$window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
     if ($button) {
      Invoke $button
      if ($dataPrompt) { "Data prompt answered: $deleteData" | Add-Content "$work/results.txt"; return }
      $confirmed=$true
     }
    }
   }
   Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  throw 'Uninstall data prompt did not appear'
 }
 function FinishUninstall($process) {
  $deadline=(Get-Date).AddSeconds(180)
  do {
   if ($process.HasExited) { return }
   [InstallerTestWindow]::DismissCompletion($process.Id)
   Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  throw 'Uninstaller did not exit'
 }
 AnswerUninstall $false
 FinishUninstall $uninstall
 WaitFor { !(Test-Path "$install/current/MSM5xxx.Desktop.exe") } | Out-Null
 Require (Test-Path "$env:MSM5XXX_STATE_DIR/retention-test.txt") 'Uninstall No preserves saved data'
 Require (!(Test-Path $shortcut)) 'Uninstall removes owned desktop shortcut'
 Start-Process "$releaseFeed/MSM5xxx-win-Setup.exe"
 WaitFor { ById 'app-menu' } | Out-Null
 $window=WindowFor 'app-menu'
 $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
 WaitFor { !(Get-Process MSM5xxx.Desktop -ErrorAction SilentlyContinue | Where-Object {$_.Path -like "$install*"}) } | Out-Null
 $uninstall=Start-Process "$install/Update.exe" -ArgumentList 'uninstall' -PassThru
 AnswerUninstall $true
 FinishUninstall $uninstall
 WaitFor { !(Test-Path "$install/current/MSM5xxx.Desktop.exe") } | Out-Null
 Require (!(Test-Path $env:MSM5XXX_STATE_DIR)) 'Uninstall Yes removes saved data'
 'PASS' | Set-Content "$work/result.txt"
} catch { $_ | Out-String | Set-Content "$work/error.txt"; 'FAIL' | Set-Content "$work/result.txt"; exit 1 }
