using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Msm5xxx.Desktop.Core;

/// <summary>Owns backend descendants, including Python interpreter redirectors, on Windows.</summary>
internal sealed class BackendProcessJob : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public nuint MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcesses;
        public nuint Affinity;
        public uint Priority, Scheduling;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        public nuint ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry
    {
        public uint Size, Usage, Id;
        public nuint DefaultHeap;
        public uint Module, Threads, ParentId;
        public int Priority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Executable;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(nint attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref ExtendedLimits information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(SafeProcessHandle process, SafeFileHandle job, [MarshalAs(UnmanagedType.Bool)] out bool contained);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry entry);

    private readonly SafeFileHandle handle;
    private BackendProcessJob(SafeFileHandle handle) => this.handle = handle;

    public static BackendProcessJob? Attach(Process backend)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var handle = CreateJobObjectW(0, null);
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        var job = new BackendProcessJob(handle);
        try
        {
            var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE.
            if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            job.Assign(backend);
            // A venv redirector can start its interpreter before Process.Start returns.
            // Adopt those existing descendants before hello, and therefore before any QEMU launch.
            var children = SnapshotChildren();
            var pending = new Queue<uint>(); pending.Enqueue((uint)backend.Id);
            var visited = new HashSet<uint>();
            while (pending.TryDequeue(out var parent))
                if (visited.Add(parent) && children.TryGetValue(parent, out var ids))
                    foreach (var id in ids)
                    {
                        try { using var process = Process.GetProcessById((int)id); job.Assign(process); pending.Enqueue(id); }
                        catch (ArgumentException) { }
                        catch (InvalidOperationException) { }
                    }
            return job;
        }
        catch { job.Dispose(); throw; }
    }

    private void Assign(Process process)
    {
        if (process.HasExited) return;
        if (!IsProcessInJob(process.SafeHandle, handle, out var contained)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!contained && !AssignProcessToJobObject(handle, process.SafeHandle)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private static Dictionary<uint, List<uint>> SnapshotChildren()
    {
        using var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>(), Executable = "" };
        var children = new Dictionary<uint, List<uint>>();
        if (!Process32FirstW(snapshot, ref entry)) throw new Win32Exception(Marshal.GetLastWin32Error());
        do
        {
            if (!children.TryGetValue(entry.ParentId, out var ids)) children[entry.ParentId] = ids = [];
            ids.Add(entry.Id);
        } while (Process32NextW(snapshot, ref entry));
        return children;
    }

    public void Dispose() => handle.Dispose();
}
