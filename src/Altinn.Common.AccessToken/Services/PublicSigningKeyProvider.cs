using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Altinn.Common.AccessToken.Configuration;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Services;

/// <summary>
/// An implementation of <see cref="IPublicSigningKeyProvider"/> that will look for the public key of a
/// given issuer in a key Vault. The public key is cached for a configurable time to avoid unnecessary
/// calls to the key vault.
/// </summary>
[ExcludeFromCodeCoverage]
public class PublicSigningKeyProvider : IPublicSigningKeyProvider
{
    private readonly AccessTokenSettings _accessTokenSettings;
    private readonly IMemoryCache _memoryCache;
    private readonly SecretClient _secretClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicSigningKeyProvider"/> class with the
    /// given settings and memory cache object.
    /// </summary>
    /// <param name="keyVaultSettings">The keyvault settings</param>
    /// <param name="accessTokenSettings">Settings for access token</param>
    /// <param name="memoryCache">Memory cache instance</param>
    public PublicSigningKeyProvider(
        IOptions<KeyVaultSettings> keyVaultSettings,
        IOptions<AccessTokenSettings> accessTokenSettings,
        IMemoryCache memoryCache)
    {
        _accessTokenSettings = accessTokenSettings.Value;
        _memoryCache = memoryCache;

        if (Environment.GetEnvironmentVariable("AZURE_CLIENT_ID") is null)
        {
            Environment.SetEnvironmentVariable("AZURE_CLIENT_ID", keyVaultSettings.Value.ClientId);
            Environment.SetEnvironmentVariable("AZURE_CLIENT_SECRET", keyVaultSettings.Value.ClientSecret);
            Environment.SetEnvironmentVariable("AZURE_TENANT_ID", keyVaultSettings.Value.TenantId);
        }

        _secretClient = new SecretClient(new Uri(keyVaultSettings.Value.SecretUri), new DefaultAzureCredential());
    }

    /// <summary>
    /// Returns the public key of the given issuer as a <see cref="SecurityKey"/>
    /// </summary>
    /// <param name="issuer">The issuer</param>
    /// <returns>The public key of the issuer</returns>
    public async Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer)
    {
        List<SecurityKey> signingKeys = new List<SecurityKey>();
        X509Certificate2 cert = await GetSigningCertFromKeyVault(issuer);

        SecurityKey key = new X509SecurityKey(cert);
        signingKeys.Add(key);

        return signingKeys;
    }

    /// <summary>
    /// Get the public key of the given issuer from a key vault and cache it for a configurable time.
    /// </summary>
    /// <param name="issuer">The token issuer</param>
    /// <returns>Returns the issuer public key as a x509 sertificate object.</returns>
    private async Task<X509Certificate2> GetSigningCertFromKeyVault(string issuer)
    {
        string cacheKey = $"cert-access-token-{issuer}";

        if (!_memoryCache.TryGetValue(cacheKey, out X509Certificate2 cert))
        {
            string secretName = $"{issuer}-access-token-public-cert";

            KeyVaultSecret keyVaultSecret = await _secretClient.GetSecretAsync(secretName);

            byte[] certBytes = Convert.FromBase64String(keyVaultSecret.Value);

#if NET9_0_OR_GREATER
            cert = X509CertificateLoader.LoadCertificate(certBytes);
#elif NET8_0
            cert = new X509Certificate2(certBytes);
#else
#error This code block does not match csproj TargetFrameworks list
#endif

            MemoryCacheEntryOptions cacheEntryOptions = new MemoryCacheEntryOptions()
           .SetPriority(CacheItemPriority.High)
           .SetAbsoluteExpiration(new TimeSpan(0, 0, _accessTokenSettings.CacheCertLifetimeInSeconds));

            _memoryCache.Set(cacheKey, cert, cacheEntryOptions);
        }

        return cert;
    }
}
