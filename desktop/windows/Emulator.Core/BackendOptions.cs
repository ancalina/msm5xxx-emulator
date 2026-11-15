using System.Diagnostics;
using System.Text;

namespace Msm5xxx.Desktop.Core;

public sealed record BackendOptions(string Bundle, string Qemu, string? Python = null, string? StateDirectory = null)
{
    public static BackendOptions Discover(string? applicationDirectory = null)
    {
        var directory = new DirectoryInfo(applicationDirectory ?? AppContext.BaseDirectory);
        var bundle = Environment.GetEnvironmentVariable("MSM5XXX_BUNDLE");
        if (string.IsNullOrWhiteSpace(bundle))
        {
            for (var current = directory; current is not null; current = current.Parent)
                if (Directory.Exists(Path.Combine(current.FullName, "src")) && Directory.Exists(Path.Combine(current.FullName, "bin")))
                { bundle = current.FullName; break; }
            bundle ??= directory.Name.Equals("bin", StringComparison.OrdinalIgnoreCase) ? directory.Parent!.FullName : directory.FullName;
        }
        bundle = Path.GetFullPath(bundle);
        return new(bundle, Environment.GetEnvironmentVariable("MSM5XXX_QEMU") ?? Path.Combine(bundle, "bin", "qemu-system-arm.exe"),
            Environment.GetEnvironmentVariable("MSM5XXX_PYTHON"), Environment.GetEnvironmentVariable("MSM5XXX_STATE_DIR"));
    }

    public IEnumerable<ProcessStartInfo> StartCandidates()
    {
        var interpreters = new List<(string File, bool Launcher)>();
        if (!string.IsNullOrWhiteSpace(Python)) interpreters.Add((Python, false));
        else
        {
            var bundled = new[] { Path.Combine(Bundle, "python", "python.exe"), Path.Combine(Bundle, "python", "python3.exe") }.FirstOrDefault(File.Exists);
            if (bundled is not null) interpreters.Add((bundled, false));
            else { interpreters.Add(("py", true)); interpreters.Add(("python", false)); }
        }
        foreach (var (file, launcher) in interpreters)
        {
            var info = new ProcessStartInfo(file)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8, WorkingDirectory = Bundle
            };
            if (launcher) info.ArgumentList.Add("-3");
            foreach (var argument in new[] { "-m", "msm5xxx_emulator.backend", "--qemu", Qemu }) info.ArgumentList.Add(argument);
            info.Environment["PYTHONPATH"] = Path.Combine(Bundle, "src");
            info.Environment["PYTHONIOENCODING"] = "utf-8";
            info.Environment["PYTHONUNBUFFERED"] = "1";
            if (StateDirectory is not null) info.Environment["MSM5XXX_STATE_DIR"] = StateDirectory;
            yield return info;
        }
    }
}
