using IOPath = System.IO.Path;

namespace Altinn.AccessToken.Tests.Utils;

internal class TempDir
    : IDisposable
{
    private readonly DirectoryInfo _dir;

    public TempDir()
    {
        _dir = null!;
        while (_dir is null)
        {
            var dir = IOPath.Combine(IOPath.GetTempPath(), IOPath.GetRandomFileName());
            if (Directory.Exists(dir))
            {
                continue;
            }

            _dir = Directory.CreateDirectory(dir);
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir.FullName, recursive: true);
        }
        catch
        {
            // Ignore
        }
    }

    public DirectoryInfo Dir => _dir;

    public string Path => _dir.FullName;
}
