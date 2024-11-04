using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.KeyProvider;

/// <summary>
/// A local (development only) certificate provider that creates self-signed certificates on the fly.
/// </summary>
internal class LocalCertificatePublicSigningKeyProvider
    : X509CertificateBasedSigningKeyProvider
    , ISigningCredentialsProvider
{
    private readonly IOptionsMonitor<Settings> _settings;

    /// <summary>
    /// Initializes a new instance of the <see cref="LocalCertificatePublicSigningKeyProvider"/> class.
    /// </summary>
    public LocalCertificatePublicSigningKeyProvider(IOptionsMonitor<Settings> settings)
    {
        _settings = settings;
    }

    /// <inheritdoc/>
    public Task<SigningCredentials> GetSigningCredentials(CancellationToken cancellationToken = default)
    {
        var cert = GetCertificate(_settings.CurrentValue.SigningIssuer!, create: true)!;

        var credentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
        return Task.FromResult<SigningCredentials>(credentials);
    }

    /// <inheritdoc/>
    protected override Task<X509Certificate2?> GetCertificate(string issuer, CancellationToken cancellationToken)
        => Task.FromResult(GetCertificate(issuer, create: false));

    private X509Certificate2? GetCertificate(string issuer, bool create)
    {
        var file = Path.Combine(_settings.CurrentValue.CertificatesDirectory!, $"{issuer}.pfx");

        if (!File.Exists(file))
        {
            return create ? CreateCertificate(file, issuer) : null;
        }

        return new(file);
    }

    private X509Certificate2 CreateCertificate(string path, string issuer)
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

        using var cert = req.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow.AddDays(-1),
            notAfter: DateTimeOffset.UtcNow.AddDays(3650));

        File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx));
        return new(path);
    }

    /// <summary>
    /// Settings for the key provider.
    /// </summary>
    internal sealed class Settings
        : IValidatableObject
    {
        /// <summary>
        /// Gets or sets the directory where the certificates are stored.
        /// </summary>
        public string? CertificatesDirectory { get; set; }

        /// <summary>
        /// Gets or sets the issuer name to use when signing tokens.
        /// </summary>
        public string? SigningIssuer { get; set; } = "local";

        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrEmpty(CertificatesDirectory))
            {
                yield return new ValidationResult("CertificatesDirectory must be set", [nameof(CertificatesDirectory)]);
            }

            if (string.IsNullOrEmpty(SigningIssuer))
            {
                yield return new ValidationResult("SigningIssuer must be set", [nameof(SigningIssuer)]);
            }
        }
    }
}
