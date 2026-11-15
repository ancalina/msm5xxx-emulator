using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace Msm5xxx.Desktop.Core;

public sealed class BackendException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>Exactly one writer and reader own the line protocol. Cancellation never abandons a reply.</summary>
public sealed class BackendClient : IAsyncDisposable
{
    private sealed record Request(string Method, object? Parameters, CancellationToken Cancellation,
        TaskCompletionSource<JsonElement> Completion);
    private readonly Channel<Request> requests = Channel.CreateUnbounded<Request>(new() { SingleReader = true });
    private readonly TextReader reader;
    private readonly TextWriter writer;
    private readonly CancellationTokenSource lifetime = new();
    private readonly Task pump;
    private readonly Process? process;
    private readonly Task? stderrPump;
    private BackendProcessJob? processJob;
    private readonly StringBuilder diagnostics = new();
    private StreamWriter? protocolLog;
    private int closing;
    private long nextId;

    public BackendClient(TextReader reader, TextWriter writer)
    {
        this.reader = reader;
        this.writer = writer;
        pump = Task.Run(PumpAsync);
    }

    private BackendClient(Process process) : this(process.StandardOutput, process.StandardInput)
    {
        this.process = process;
        var logDirectory = Environment.GetEnvironmentVariable("MSM5XXX_PROTOCOL_LOG_DIR");
        if (!string.IsNullOrWhiteSpace(logDirectory))
            try
            {
                Directory.CreateDirectory(logDirectory);
                protocolLog = new StreamWriter(Path.Combine(logDirectory, $"backend-{process.Id}-{Guid.NewGuid():N}.jsonl"), append: false, new UTF8Encoding(false)) { AutoFlush = true };
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
        stderrPump = Task.Run(async () =>
        {
            var buffer = new char[2048];
            int count;
            try
            {
                while ((count = await process.StandardError.ReadAsync(buffer.AsMemory(), lifetime.Token)) != 0)
                    lock (diagnostics)
                    {
                        diagnostics.Append(buffer, 0, count);
                        if (diagnostics.Length > 16384) diagnostics.Remove(0, diagnostics.Length - 16384);
                    }
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        });
    }

    public string Diagnostics { get { lock (diagnostics) return diagnostics.ToString(); } }
    public bool IsConnected => Volatile.Read(ref closing) == 0 && !pump.IsCompleted;

    private void Trace(string direction, long id, string method, object? parameters = null, object? result = null)
    {
        if (protocolLog is null) return;
        try { protocolLog.WriteLine(JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, direction, id, method, parameters, result })); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            try { protocolLog.Dispose(); } catch (IOException) { }
            protocolLog = null;
        }
    }

    public static async Task<BackendClient> StartAsync(BackendOptions options)
    {
        Exception? failure = null;
        foreach (var start in options.StartCandidates())
        {
            BackendClient? client = null;
            try
            {
                var process = Process.Start(start) ?? throw new IOException("Backend process did not start.");
                client = new BackendClient(process);
                client.processJob = BackendProcessJob.Attach(process);
                var hello = await client.CallAsync("hello").WaitAsync(TimeSpan.FromSeconds(30));
                if (hello.GetProperty("protocol").GetInt32() != 1)
                    throw new IOException("Unsupported backend protocol.");
                return client;
            }
            catch (Exception error)
            {
                failure = new IOException(error.Message + (client is null ? "" : "\n" + client.Diagnostics), error);
                if (client is not null) await client.DisposeAsync();
            }
        }
        throw failure ?? new IOException("No Python interpreter is available.");
    }

    public Task<JsonElement> CallAsync(string method, object? parameters = null, CancellationToken cancellation = default)
    {
        if (Volatile.Read(ref closing) != 0) return Task.FromException<JsonElement>(new ObjectDisposedException(nameof(BackendClient)));
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!requests.Writer.TryWrite(new(method, parameters, cancellation, completion)))
            completion.TrySetException(new IOException("Backend connection is closed."));
        return completion.Task.WaitAsync(cancellation);
    }

    private async Task PumpAsync()
    {
        Exception terminal = new IOException("Backend connection is closed.");
        try
        {
            await foreach (var request in requests.Reader.ReadAllAsync(lifetime.Token))
            {
                if (request.Cancellation.IsCancellationRequested)
                {
                    request.Completion.TrySetCanceled(request.Cancellation);
                    continue;
                }
                try
                {
                    var id = ++nextId;
                    var line = JsonSerializer.Serialize(new { id, method = request.Method, @params = request.Parameters ?? new { } });
                    await writer.WriteLineAsync(line.AsMemory(), lifetime.Token);
                    await writer.FlushAsync(lifetime.Token);
                    Trace("sent", id, request.Method, request.Parameters);
                    var reply = await reader.ReadLineAsync(lifetime.Token) ?? throw new EndOfStreamException("Backend exited. " + Diagnostics);
                    using var document = JsonDocument.Parse(reply);
                    var root = document.RootElement;
                    if (root.GetProperty("id").GetInt64() != id) throw new IOException("Backend reply ID mismatch.");
                    object? summary = null;
                    if (protocolLog is not null && root.TryGetProperty("result", out var result))
                    {
                        if (request.Method == "session.frame")
                        {
                            var fields = new Dictionary<string, JsonElement>();
                            foreach (var key in new[] { "running", "seq", "width", "height" })
                                if (result.TryGetProperty(key, out var field)) fields[key] = field;
                            summary = fields;
                        }
                        else if (request.Method == "session.key") summary = result.GetBoolean();
                    }
                    Trace("received", id, request.Method, result: summary);
                    if (root.TryGetProperty("error", out var error))
                        request.Completion.TrySetException(new BackendException(error.GetProperty("code").GetString()!, error.GetProperty("message").GetString()!));
                    else request.Completion.TrySetResult(root.GetProperty("result").Clone());
                }
                catch (Exception error)
                {
                    request.Completion.TrySetException(error);
                    throw;
                }
            }
        }
        catch (Exception error) { terminal = error; }
        finally
        {
            requests.Writer.TryComplete();
            while (requests.Reader.TryRead(out var request)) request.Completion.TrySetException(terminal);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref closing, 1) != 0) return;
        requests.Writer.TryComplete();
        // Closing stdin is the backend's unconditional session cleanup path.
        try { writer.Dispose(); }
        catch (IOException) { /* A backend that has already exited may have closed the pipe. */ }
        if (process is not null)
        {
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (TimeoutException)
            {
                if (processJob is not null) processJob.Dispose();
                else
                    try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                    catch (InvalidOperationException) when (process.HasExited) { }
                await process.WaitForExitAsync();
            }
        }
        processJob?.Dispose();
        lifetime.Cancel();
        await pump;
        try { protocolLog?.Dispose(); } catch (IOException) { }
        if (stderrPump is not null) await stderrPump;
        reader.Dispose();
        process?.Dispose();
        lifetime.Dispose();
    }
}
