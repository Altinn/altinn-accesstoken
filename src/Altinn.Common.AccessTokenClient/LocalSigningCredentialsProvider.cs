using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.KeyProvider;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessTokenClient;

/// <summary>
/// Implementation of <see cref="ISigningCredentialsProvider"/> that provides a <see cref="SigningCredentials"/> based on a local certificate.
/// </summary>
internal class LocalSigningCredentialsProvider
    : ISigningCredentialsProvider
{
    private readonly Lazy<SigningCredentials> _x509SigningCredentials;

    /// <summary>
    /// Initializes a new instance of the <see cref="LocalSigningCredentialsProvider"/> class.
    /// </summary>
    /// <param name="accessTokenSettings">Access token settings</param>
    public LocalSigningCredentialsProvider(IOptions<Settings> accessTokenSettings)
    {
        _x509SigningCredentials = new Lazy<SigningCredentials>(
            CreateSigningCredentialsFactory(accessTokenSettings.Value),
            LazyThreadSafetyMode.PublicationOnly);

        // method to prevent overeager capture of the settings object
        static Func<SigningCredentials> CreateSigningCredentialsFactory(Settings accessTokenSettings)
            => () => GetSigningCredentials(accessTokenSettings);
    }

    /// <inheritdoc/>
    public Task<SigningCredentials> GetSigningCredentials(CancellationToken cancellationToken = default)
        => Task.FromResult(_x509SigningCredentials.Value);

    private static SigningCredentials GetSigningCredentials(Settings accessTokenSettings)
    {
        var cert = new X509Certificate2(accessTokenSettings.CertificatePath!);
        
        return new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
    }

    /// <summary>
    /// Settings for <see cref="LocalSigningCredentialsProvider"/>.
    /// </summary>
    internal sealed class Settings
        : IValidatableObject
    {
        /// <summary>
        /// Gets or sets the path to the certificate file.
        /// </summary>
        public string? CertificatePath { get; set; }

        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(CertificatePath))
            {
                yield return new ValidationResult("Certificate path must be set.", [nameof(CertificatePath)]);
            }

            if (!File.Exists(CertificatePath))
            {
                yield return new ValidationResult("Certificate file does not exist.", [nameof(CertificatePath)]);
            }
        }
    }
}
