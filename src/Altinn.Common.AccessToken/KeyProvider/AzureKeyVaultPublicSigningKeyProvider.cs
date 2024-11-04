using System;
using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Altinn.Common.AccessToken.KeyProvider;

/// <summary>
/// An implementation of <see cref="IPublicSigningKeyProvider"/> that will look for the public key of a
/// given issuer in a key Vault. The public key is cached for a configurable time to avoid unnecessary
/// calls to the key vault.
/// </summary>
internal class AzureKeyVaultPublicSigningKeyProvider 
    : X509CertificateBasedSigningKeyProvider
{
    private readonly AccessTokenSettings _accessTokenSettings;
    private readonly IMemoryCache _memoryCache;
    private readonly SecretClient _secretClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultPublicSigningKeyProvider"/> class with the
    /// given settings and memory cache object.
    /// </summary>
    /// <param name="secretClient">The keyvault secret client</param>
    /// <param name="accessTokenSettings">Settings for access token</param>
    /// <param name="memoryCache">Memory cache instance</param>
    public AzureKeyVaultPublicSigningKeyProvider(
        [FromKeyedServices(typeof(IPublicSigningKeyProvider))] SecretClient secretClient,
        IOptions<AccessTokenSettings> accessTokenSettings,
        IMemoryCache memoryCache)
    {
        _accessTokenSettings = accessTokenSettings.Value;
        _memoryCache = memoryCache;
        _secretClient = secretClient;
    }

    /// <inheritdoc/>
    protected override async Task<X509Certificate2?> GetCertificate(string issuer, CancellationToken cancellationToken)
    {
        var certificate = await _memoryCache.GetOrCreateAsync(new SigningCertKey(issuer), async (opts) =>
        {
            opts.SetPriority(CacheItemPriority.High)
                .SetAbsoluteExpiration(TimeSpan.FromSeconds(_accessTokenSettings.CacheCertLifetimeInSeconds));

            string issuer = ((SigningCertKey)opts.Key).Issuer;
            string secretName = $"{issuer}-access-token-public-cert";

            KeyVaultSecret keyVaultSecret = await _secretClient.GetSecretAsync(secretName, cancellationToken: cancellationToken);

            int base64MaxLength = Base64.GetMaxDecodedFromUtf8Length(keyVaultSecret.Value.Length);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(base64MaxLength);
            X509Certificate2 cert;

            try
            {
                if (!Convert.TryFromBase64String(keyVaultSecret.Value, buffer, out var written))
                {
                    throw new Exception("Failed to decode base64 string");
                }

                cert = new X509Certificate2(buffer.AsSpan(0, written));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return cert;
        });

        return certificate;
    }

    private sealed record SigningCertKey(string Issuer);
}
