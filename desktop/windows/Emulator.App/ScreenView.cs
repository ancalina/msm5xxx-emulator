using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Msm5xxx.Desktop.Core;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace Msm5xxx.Desktop;

/// <summary>Renders LCD pixels to physical output pixels before WinUI composition, avoiding interpolation.</summary>
public sealed class ScreenView : Grid
{
    private readonly Image image = new() { Stretch = Stretch.Fill, HorizontalAlignment = HorizontalAlignment.Stretch, VerticalAlignment = VerticalAlignment.Stretch };
    private RgbFrame? frame;
    private bool rendering;
    private long version;
    private long generation;
    private bool stopped;
    public RgbFrame? Frame => frame;

    public ScreenView(string name)
    {
        Background = new SolidColorBrush(Microsoft.UI.Colors.Black);
        Children.Add(image);
        SetAccessibleName(name);
        SizeChanged += (_, _) => Schedule();
        Loaded += (_, _) =>
        {
            XamlRoot.Changed += (_, _) => Schedule();
            Schedule();
        };
    }

    public void ShowFrame(RgbFrame value) { frame = value; Schedule(); }
    public void Clear() { generation++; frame = null; image.Source = null; version++; }
    public void SetAccessibleName(string name)
    {
        AutomationProperties.SetName(this, name);
        AutomationProperties.SetName(image, name);
    }
    public void Stop() { stopped = true; frame = null; image.Source = null; version++; }

    private void Schedule()
    {
        version++;
        if (!rendering && !stopped) _ = RenderAsync();
    }

    private async Task RenderAsync()
    {
        rendering = true;
        try
        {
            long rendered;
            do
            {
                rendered = version;
                if (frame is null || XamlRoot is null || ActualWidth < 1 || ActualHeight < 1 || stopped) return;
                var current = frame;
                var currentGeneration = generation;
                var w = Math.Max(1, (int)Math.Round(ActualWidth * XamlRoot.RasterizationScale));
                var h = Math.Max(1, (int)Math.Round(ActualHeight * XamlRoot.RasterizationScale));
                var pixels = await Task.Run(() => current.Render(w, h));
                if (stopped) return;
                if (currentGeneration != generation) continue;
                // A resized output is rendered again before presenting, avoiding blurred intermediate scaling.
                if (Math.Abs(ActualWidth * XamlRoot.RasterizationScale - w) > 1 || Math.Abs(ActualHeight * XamlRoot.RasterizationScale - h) > 1) continue;
                var bitmap = image.Source as WriteableBitmap;
                if (bitmap is null || bitmap.PixelWidth != w || bitmap.PixelHeight != h) bitmap = new(w, h);
                using (var target = bitmap.PixelBuffer.AsStream()) await target.WriteAsync(pixels);
                if (stopped) return;
                if (currentGeneration != generation) continue;
                bitmap.Invalidate(); image.Source = bitmap;
            } while (rendered != version && !stopped);
        }
        catch (Exception error) { RenderFailed?.Invoke(error); }
        finally { rendering = false; }
    }

    public event Action<Exception>? RenderFailed;

    public static async Task SavePngAsync(RgbFrame frame, string path)
    {
        var pixels = await Task.Run(() => frame.Render(frame.Width, frame.Height));
        using var stream = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Ignore, (uint)frame.Width, (uint)frame.Height, 96, 96, pixels);
        await encoder.FlushAsync();
        stream.Seek(0);
        using var source = stream.AsStreamForRead();
        var destinationPath = Path.GetFullPath(path);
        var temporaryPath = Path.Combine(Path.GetDirectoryName(destinationPath)!,
            ".msm5xxx-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var destination = new FileStream(temporaryPath, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                await source.CopyToAsync(destination);
                await destination.FlushAsync();
            }
            if (File.Exists(destinationPath))
                File.Replace(temporaryPath, destinationPath, destinationBackupFileName: null);
            else
                File.Move(temporaryPath, destinationPath);
        }
        finally
        {
            try { File.Delete(temporaryPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
