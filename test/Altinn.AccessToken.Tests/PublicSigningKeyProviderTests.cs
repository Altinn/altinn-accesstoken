using System.Security.Cryptography.X509Certificates;

using Altinn.AccessToken.Tests.Mock;

using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessToken.Services;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.AccessToken.Tests;

public class PublicSigningKeyProviderTests
{
    [Fact]
    public async Task GetSigningKeys_NoKeyVaultAndPemPath_ReturnsCertificateForAnyIssuer()
    {
        // Arrange
        var target = CreateProvider(Path.Combine(AppContext.BaseDirectory, "ttd-org.pem"));

        // Act
        IEnumerable<SecurityKey> ttdKeys = await target.GetSigningKeys("ttd");
        IEnumerable<SecurityKey> otherKeys = await target.GetSigningKeys("platform");

        // Assert
        string expected = await GetTtdThumbprint();
        Assert.Equal(expected, GetCertificate(ttdKeys).Thumbprint);
        Assert.Equal(expected, GetCertificate(otherKeys).Thumbprint);
    }

    [Fact]
    public async Task GetSigningKeys_NoKeyVaultAndPfxPath_ReturnsPublicPartOnly()
    {
        // Arrange
        var target = CreateProvider(Path.Combine(AppContext.BaseDirectory, "ttd-org.pfx"));

        // Act
        IEnumerable<SecurityKey> keys = await target.GetSigningKeys("ttd");

        // Assert
        X509Certificate2 cert = GetCertificate(keys);
        Assert.Equal(await GetTtdThumbprint(), cert.Thumbprint);
        Assert.False(cert.HasPrivateKey);
    }

    [Fact]
    public async Task GetSigningKeys_PathWithIssuerPlaceholder_ReadsFileOfIssuer()
    {
        // Arrange
        var target = CreateProvider(Path.Combine(AppContext.BaseDirectory, "{issuer}-org.pem"));

        // Act
        IEnumerable<SecurityKey> keys = await target.GetSigningKeys("ttd");

        // Assert
        Assert.Equal(await GetTtdThumbprint(), GetCertificate(keys).Thumbprint);
    }

    [Fact]
    public async Task GetSigningKeys_PathWithIssuerPlaceholderAndNoFileForIssuer_ThrowsFileNotFoundException()
    {
        // Arrange
        var target = CreateProvider(Path.Combine(AppContext.BaseDirectory, "{issuer}-org.pem"));

        // Act & Assert
        var ex = await Assert.ThrowsAsync<FileNotFoundException>(() => target.GetSigningKeys("unknown"));
        Assert.EndsWith("unknown-org.pem", ex.FileName);
    }

    [Theory]
    [InlineData("../ttd")]
    [InlineData("..\\ttd")]
    [InlineData("sub/ttd")]
    [InlineData("..")]
    [InlineData("")]
    public async Task GetSigningKeys_IssuerIsNotAFileName_ThrowsArgumentException(string issuer)
    {
        // Arrange
        string folder = Path.Combine(AppContext.BaseDirectory, "sub");
        var target = CreateProvider(Path.Combine(folder, "{issuer}-org.pem"));

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => target.GetSigningKeys(issuer));
    }

    [Fact]
    public async Task GetSigningKeys_NoKeyVaultAndNoPath_ThrowsInvalidOperationException()
    {
        // Arrange
        var target = CreateProvider(null);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => target.GetSigningKeys("ttd"));
        Assert.Contains(nameof(AccessTokenSettings.PublicSigningCertificatePath), ex.Message);
    }

    [Fact]
    public async Task GetSigningKeys_CalledTwice_ReadsFileOnce()
    {
        // Arrange
        string folder = Directory.CreateTempSubdirectory("accesstoken-tests-").FullName;
        string path = Path.Combine(folder, "cert.pem");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "ttd-org.pem"), path);

        var target = CreateProvider(path);

        try
        {
            await target.GetSigningKeys("ttd");
            File.Delete(path);

            // Act
            IEnumerable<SecurityKey> keys = await target.GetSigningKeys("ttd");

            // Assert
            Assert.Equal(await GetTtdThumbprint(), GetCertificate(keys).Thumbprint);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task Validate_NoKeyVaultAndTokenSignedWithLocalCertificate_ReturnsTrue()
    {
        // Arrange
        var provider = CreateProvider(Path.Combine(AppContext.BaseDirectory, "ttd-org.pfx"));
        var target = new AccessTokenValidator(provider, new Mock<ILogger<AccessTokenValidator>>().Object);

        string token = AccessTokenCreator.GenerateToken(PrincipalUtil.CreateClaimsPrincipal(), -5, 60, "ttd");

        // Act
        bool result = await target.Validate(token);

        // Assert
        Assert.True(result);
    }

    private static PublicSigningKeyProvider CreateProvider(string? path)
    {
        return new PublicSigningKeyProvider(
            Options.Create(new KeyVaultSettings()),
            Options.Create(new AccessTokenSettings { PublicSigningCertificatePath = path }),
            new MemoryCache(new MemoryCacheOptions()));
    }

    private static X509Certificate2 GetCertificate(IEnumerable<SecurityKey> keys)
    {
        return Assert.IsType<X509SecurityKey>(Assert.Single(keys)).Certificate;
    }

    private static async Task<string> GetTtdThumbprint()
    {
        return GetCertificate(await new PublicSigningKeyProviderMock().GetSigningKeys("ttd")).Thumbprint;
    }
}
