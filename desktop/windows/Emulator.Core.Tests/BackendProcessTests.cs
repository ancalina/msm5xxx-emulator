using System.Diagnostics;
using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Tests;

public class BackendProcessTests
{
    [Fact]
    public async Task StdinCloseTerminatesAnUncooperativeBackendAndItsPipeInheritingChild()
    {
        var root = Path.Combine(Path.GetTempPath(), "msm5xxx-process-tests", Guid.NewGuid().ToString("N"));
        var package = Path.Combine(root, "src", "msm5xxx_emulator");
        Directory.CreateDirectory(package);
        await File.WriteAllTextAsync(Path.Combine(package, "__init__.py"), "");
        await File.WriteAllTextAsync(Path.Combine(package, "backend.py"), """
            import json, os, pathlib, subprocess, sys, time
            root = pathlib.Path(os.environ["MSM5XXX_STATE_DIR"])
            root.mkdir(parents=True, exist_ok=True)
            for line in sys.stdin:
                request = json.loads(line)
                print(json.dumps({"id": request["id"], "result": {"protocol": 1, "language": "en", "state_root": str(root)}}), flush=True)
            child = subprocess.Popen([sys.executable, "-c", "import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(60)", str(root / "child-real.pid")])
            (root / "child.pid").write_text(str(child.pid))
            (root / "stdin-closed").write_text("yes")
            while True:
                time.sleep(1)
            """);
        var python = Environment.GetEnvironmentVariable("MSM5XXX_PYTHON") ?? (OperatingSystem.IsWindows() ? "python" : "python3");
        try
        {
            var client = await BackendClient.StartAsync(new BackendOptions(root, "unused-qemu", python, root));
            var elapsed = Stopwatch.StartNew();
            await client.DisposeAsync();
            Assert.InRange(elapsed.Elapsed.TotalSeconds, 9.5, 30);
            Assert.True(File.Exists(Path.Combine(root, "stdin-closed")));
            foreach (var name in new[] { "child.pid", "child-real.pid" })
            {
                var id = int.Parse(await File.ReadAllTextAsync(Path.Combine(root, name)));
                var exited = false;
                for (var attempt = 0; attempt < 40 && !exited; attempt++)
                {
                    try { using var process = Process.GetProcessById(id); exited = process.HasExited; }
                    catch (ArgumentException) { exited = true; }
                    if (!exited) await Task.Delay(50);
                }
                Assert.True(exited, $"Backend child {id} survived shutdown.");
            }
        }
        finally
        {
            foreach (var name in new[] { "child.pid", "child-real.pid" })
                try
                {
                    var path = Path.Combine(root, name);
                    if (!File.Exists(path)) continue;
                    using var child = Process.GetProcessById(int.Parse(await File.ReadAllTextAsync(path)));
                    // Reject reused PIDs: these files are written immediately after child creation.
                    if (!child.HasExited && Math.Abs((child.StartTime.ToUniversalTime() - File.GetLastWriteTimeUtc(path)).TotalSeconds) < 5)
                    {
                        child.Kill(entireProcessTree: true);
                        await child.WaitForExitAsync();
                    }
                }
                catch (Exception error) when (error is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or IOException) { }
            Directory.Delete(root, recursive: true);
        }
    }
}
