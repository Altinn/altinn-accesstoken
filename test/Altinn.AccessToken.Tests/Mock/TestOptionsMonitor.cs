using Microsoft.Extensions.Options;

namespace Altinn.AccessToken.Tests.Mock;

public static class TestOptionsMonitor
{
    public static TestOptionsMonitor<T> Create<T>(T value)
        => new(value);
}

public class TestOptionsMonitor<T>
    : IOptionsMonitor<T>
{
    private readonly T _value;

    public TestOptionsMonitor(T value)
    {
        _value = value;
    }

    public T CurrentValue => _value;

    public T Get(string? name)
    {
        throw new NotSupportedException();
    }

    public IDisposable? OnChange(Action<T, string?> listener) 
        => null;
}
