using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;

namespace Msm5xxx.Desktop;

internal sealed class TaskbarProgress : IDisposable
{
    [ComImport, Guid("EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ITaskbarList3
    {
        void HrInit();
        void AddTab(nint window);
        void DeleteTab(nint window);
        void ActivateTab(nint window);
        void SetActiveAlt(nint window);
        void MarkFullscreenWindow(nint window, [MarshalAs(UnmanagedType.Bool)] bool fullscreen);
        void SetProgressValue(nint window, ulong completed, ulong total);
        void SetProgressState(nint window, uint state);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint SubclassProcedure(nint window, uint message, nuint wParam, nint lParam, nuint id, nuint data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessage(string name);
    [DllImport("comctl32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(nint window, SubclassProcedure procedure, nuint id, nuint data);
    [DllImport("comctl32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(nint window, SubclassProcedure procedure, nuint id);
    [DllImport("comctl32.dll")]
    private static extern nint DefSubclassProc(nint window, uint message, nuint wParam, nint lParam);

    private static readonly uint ButtonCreated = RegisterWindowMessage("TaskbarButtonCreated");
    private readonly nint handle;
    private readonly SubclassProcedure procedure;
    private ITaskbarList3? taskbar;
    private bool ready, busy, disposed;

    public TaskbarProgress(Window window)
    {
        handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        procedure = HandleMessage;
        if (ButtonCreated != 0) SetWindowSubclass(handle, procedure, 2, 0);
        window.Closed += (_, _) => Dispose();
    }

    public void SetBusy(bool value) { busy = value; Apply(); }

    private void Apply()
    {
        if (!ready || disposed) return;
        try
        {
            if (taskbar is null)
            {
                taskbar = (ITaskbarList3)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("56FDF344-FD6D-11D0-958A-006097C9A090"))!)!;
                taskbar.HrInit();
            }
            taskbar.SetProgressState(handle, busy ? 1u : 0u);
        }
        catch (COMException error)
        {
            System.Diagnostics.Debug.WriteLine(error);
            if (taskbar is not null) Marshal.ReleaseComObject(taskbar);
            taskbar = null;
        }
    }

    private nint HandleMessage(nint window, uint message, nuint wParam, nint lParam, nuint id, nuint data)
    {
        try
        {
            if (message == ButtonCreated) { ready = true; Apply(); }
            else if (message == 0x0082) Dispose();
        }
        catch (Exception error) { System.Diagnostics.Debug.WriteLine(error); }
        return DefSubclassProc(window, message, wParam, lParam);
    }

    public void Dispose()
    {
        if (disposed) return;
        SetBusy(false);
        disposed = true;
        RemoveWindowSubclass(handle, procedure, 2);
        if (taskbar is not null) Marshal.ReleaseComObject(taskbar);
        taskbar = null;
        GC.KeepAlive(procedure);
    }
}
