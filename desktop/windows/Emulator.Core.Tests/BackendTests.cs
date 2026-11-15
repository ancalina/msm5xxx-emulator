using System.Text.Json;
using System.Threading.Channels;
using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Tests;

public class BackendTests
{
    private sealed class Replies : TextReader
    {
        public Channel<string> Lines { get; } = Channel.CreateUnbounded<string>();
        public override ValueTask<string?> ReadLineAsync(CancellationToken cancellationToken) => Read(cancellationToken);
        private async ValueTask<string?> Read(CancellationToken token) => await Lines.Reader.ReadAsync(token);
    }
    private sealed class Requests : StringWriter
    {
        public Channel<string> Lines { get; } = Channel.CreateUnbounded<string>();
        public override Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
        { Lines.Writer.TryWrite(buffer.ToString()); return Task.CompletedTask; }
    }

    [Fact]
    public async Task QueueSerializesCallsAndKeepsBackendErrorsRecoverable()
    {
        var replies = new Replies(); var requests = new Requests();
        await using var client = new BackendClient(replies, requests);
        var first = client.CallAsync("library.scan");
        var second = client.CallAsync("settings.get");
        using var sent = JsonDocument.Parse(await requests.Lines.Reader.ReadAsync());
        Assert.Equal("library.scan", sent.RootElement.GetProperty("method").GetString());
        Assert.False(requests.Lines.Reader.TryRead(out _));
        replies.Lines.Writer.TryWrite("{\"id\":1,\"error\":{\"code\":\"settings_error\",\"message\":\"잘못된 값\"}}");
        var error = await Assert.ThrowsAsync<BackendException>(() => first);
        Assert.Equal("잘못된 값", error.Message);
        using var next = JsonDocument.Parse(await requests.Lines.Reader.ReadAsync());
        Assert.Equal(2, next.RootElement.GetProperty("id").GetInt32());
        replies.Lines.Writer.TryWrite("{\"id\":2,\"result\":{\"ui_language\":\"ko\"}}");
        Assert.Equal("ko", (await second).GetProperty("ui_language").GetString());
    }

    [Fact]
    public async Task CancellationDrainsInFlightReplyAndSkipsUnsentRequest()
    {
        var replies = new Replies(); var requests = new Requests();
        await using var client = new BackendClient(replies, requests);
        using var inFlight = new CancellationTokenSource(); using var queued = new CancellationTokenSource();
        var first = client.CallAsync("session.frame", cancellation: inFlight.Token);
        await requests.Lines.Reader.ReadAsync();
        var skipped = client.CallAsync("session.state", cancellation: queued.Token);
        var third = client.CallAsync("settings.get");
        inFlight.Cancel(); queued.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => skipped);
        replies.Lines.Writer.TryWrite("{\"id\":1,\"result\":null}");
        using var sent = JsonDocument.Parse(await requests.Lines.Reader.ReadAsync());
        Assert.Equal("settings.get", sent.RootElement.GetProperty("method").GetString());
        Assert.Equal(2, sent.RootElement.GetProperty("id").GetInt32());
        replies.Lines.Writer.TryWrite("{\"id\":2,\"result\":true}");
        Assert.True((await third).GetBoolean());
    }

    [Theory]
    [InlineData("{\"id\":999,\"result\":null}")]
    [InlineData("broken JSON")]
    public async Task ProtocolFailureFailsEveryQueuedCall(string badReply)
    {
        var replies = new Replies(); var requests = new Requests();
        await using var client = new BackendClient(replies, requests);
        var first = client.CallAsync("hello"); var second = client.CallAsync("ui.layout");
        await requests.Lines.Reader.ReadAsync();
        replies.Lines.Writer.TryWrite(badReply);
        await Assert.ThrowsAnyAsync<Exception>(() => first);
        await Assert.ThrowsAnyAsync<Exception>(() => second);
        await Assert.ThrowsAnyAsync<Exception>(() => client.CallAsync("hello"));
    }

    [Fact]
    public async Task DisposalCompletesAnActiveReadAndRejectsFurtherCalls()
    {
        var replies = new Replies(); var requests = new Requests();
        var client = new BackendClient(replies, requests);
        var active = client.CallAsync("session.frame");
        await requests.Lines.Reader.ReadAsync();
        var queued = client.CallAsync("session.state");
        await client.DisposeAsync();
        await Assert.ThrowsAnyAsync<Exception>(() => active);
        await Assert.ThrowsAnyAsync<Exception>(() => queued);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.CallAsync("hello"));
        await client.DisposeAsync();
    }

    [Fact]
    public void ProcessArgumentsPreserveSpacesAndUseUtf8()
    {
        var start = new BackendOptions("/bundle with spaces", "/bundle with spaces/bin/qemu.exe", "/python path/python.exe", "/state path").StartCandidates().Single();
        Assert.Equal("/python path/python.exe", start.FileName);
        Assert.Equal(new[] { "-m", "msm5xxx_emulator.backend", "--qemu", "/bundle with spaces/bin/qemu.exe" }, start.ArgumentList);
        Assert.Equal(Path.Combine("/bundle with spaces", "src"), start.Environment["PYTHONPATH"]);
        Assert.Equal("/state path", start.Environment["MSM5XXX_STATE_DIR"]);
        Assert.False(start.UseShellExecute);
        Assert.Empty(start.StandardInputEncoding!.GetPreamble());
    }
}
