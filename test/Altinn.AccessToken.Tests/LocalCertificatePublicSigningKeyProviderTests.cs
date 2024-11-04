using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Altinn.AccessToken.Tests.Mock;
using Altinn.AccessToken.Tests.Utils;
using Altinn.Common.AccessToken.KeyProvider;

namespace Altinn.AccessToken.Tests;

public class LocalCertificatePublicSigningKeyProviderTests
    : IDisposable
{
    private readonly TempDir _tempDir = new();
    private readonly LocalCertificatePublicSigningKeyProvider.Settings _settings;
    private readonly LocalCertificatePublicSigningKeyProvider _sut;

    public LocalCertificatePublicSigningKeyProviderTests()
    {
        _settings = new LocalCertificatePublicSigningKeyProvider.Settings
        {
            CertificatesDirectory = _tempDir.Path,
        };

        _sut = new LocalCertificatePublicSigningKeyProvider(TestOptionsMonitor.Create(_settings));
    }

    public void Dispose()
    {
        _tempDir.Dispose();
    }

    [Theory]
    [InlineData("issuer1", true)]
    [InlineData("issuer2", false)]
    public async Task GetSigningKeys_CertificateExists_ReturnsCertificate(string issuer, bool create)
    {
        if (create)
        {
            var cert = GenerateCertificate(issuer);
            var file = Path.Combine(_settings.CertificatesDirectory!, $"{issuer}.pfx");
            File.WriteAllBytes(file, cert.Export(X509ContentType.Pfx));
        }

        var result = await _sut.GetSigningKeys(issuer);
        
        if (create)
        {
            result.Should().NotBeEmpty();
        }
        else
        {
            result.Should().BeEmpty();
        }
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
