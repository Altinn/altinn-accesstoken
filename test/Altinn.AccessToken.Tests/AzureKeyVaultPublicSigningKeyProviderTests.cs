using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Altinn.AccessToken.Tests.Utils;
using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.KeyProvider;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.AccessToken.Tests;

public class AzureKeyVaultPublicSigningKeyProviderTests
{
    private readonly Mock<SecretClient> _secretClientMock = new();
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());
    private readonly AccessTokenSettings _accessTokenSettings = new();
    private readonly AzureKeyVaultPublicSigningKeyProvider _sut;

    public AzureKeyVaultPublicSigningKeyProviderTests()
    {
        _sut = new(
            secretClient: _secretClientMock.Object,
            accessTokenSettings: Options.Create(_accessTokenSettings),
            memoryCache: _cache);
    }

    [Theory]
    [InlineData("ttd")]
    [InlineData("ttd-test")]
    public async Task GetSigningKeys_GetsCertificate_FromSecretClient(string issuer)
    {
        var expectedSecretName = $"{issuer}-access-token-public-cert";
        var cert = GenerateCertificate(issuer);
        var base64cert = Convert.ToBase64String(cert.Export(X509ContentType.Pfx));
        var getSecretCallCount = 0;

        _secretClientMock.Setup(x => x.GetSecretAsync(
            It.Is(expectedSecretName, StringComparer.Ordinal),
            It.Is(null, StringComparer.Ordinal),
            It.IsAny<CancellationToken>()))
            .Callback(() => Interlocked.Increment(ref getSecretCallCount))
            .Returns(() => CreateSecretResponse(expectedSecretName, base64cert));

        var signingKeys = await _sut.GetSigningKeys(issuer);
        var key = signingKeys.Should().ContainSingle().Which;
        key.Should().NotBeNull();
        var keyCert = key.Should().BeOfType<X509SecurityKey>().Which.Certificate;
        keyCert.Should().NotBeNull();
        keyCert.Thumbprint.Should().Be(cert.Thumbprint);

        getSecretCallCount.Should().Be(1);

        signingKeys = await _sut.GetSigningKeys(issuer);
        getSecretCallCount.Should().Be(1);
    }

    private static Task<Azure.Response<KeyVaultSecret>> CreateSecretResponse(string secretName, string value)
    {
        var secret = new KeyVaultSecret(secretName, value);
        var response = Azure.Response.FromValue(secret, response: null!);
        return Task.FromResult(response);
    }

    private static X509Certificate2 GenerateCertificate(string issuer)
    {
        using var rsa = RSA.Create(2048);
        var distinguishedName = new X500DistinguishedName($"CN={issuer}");
        var req = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
               new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        return req.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow.AddDays(-1),
            notAfter: DateTimeOffset.UtcNow.AddDays(3650));
    }
}
