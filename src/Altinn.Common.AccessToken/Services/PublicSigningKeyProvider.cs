using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
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
/// <remarks>
/// When no key vault is configured (<see cref="KeyVaultSettings.SecretUri"/> is empty) the public key is read from
/// the file given by <see cref="AccessTokenSettings.PublicSigningCertificatePath"/> instead. This is meant for
/// running locally without access to a key vault.
/// </remarks>
public class PublicSigningKeyProvider : IPublicSigningKeyProvider
{
    private const string IssuerPlaceholder = "{issuer}";

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

        if (!string.IsNullOrWhiteSpace(keyVaultSettings.Value.SecretUri))
        {
            _secretClient = CreateSecretClient(keyVaultSettings.Value);
        }
    }

    /// <summary>
    /// Returns the public key of the given issuer as a <see cref="SecurityKey"/>
    /// </summary>
    /// <param name="issuer">The issuer</param>
    /// <returns>The public key of the issuer</returns>
    public async Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer)
    {
        List<SecurityKey> signingKeys = new List<SecurityKey>();
        X509Certificate2 cert = await GetSigningCert(issuer);

        SecurityKey key = new X509SecurityKey(cert);
        signingKeys.Add(key);

        return signingKeys;
    }

    [ExcludeFromCodeCoverage]
    private static SecretClient CreateSecretClient(KeyVaultSettings keyVaultSettings)
    {
        if (Environment.GetEnvironmentVariable("AZURE_CLIENT_ID") is null)
        {
            Environment.SetEnvironmentVariable("AZURE_CLIENT_ID", keyVaultSettings.ClientId);
            Environment.SetEnvironmentVariable("AZURE_CLIENT_SECRET", keyVaultSettings.ClientSecret);
            Environment.SetEnvironmentVariable("AZURE_TENANT_ID", keyVaultSettings.TenantId);
        }

        return new SecretClient(new Uri(keyVaultSettings.SecretUri), new DefaultAzureCredential());
    }

    /// <summary>
    /// Get the public key of the given issuer from a key vault, or from a file when no key vault is configured,
    /// and cache it for a configurable time.
    /// </summary>
    /// <param name="issuer">The token issuer</param>
    /// <returns>Returns the issuer public key as a x509 sertificate object.</returns>
    private async Task<X509Certificate2> GetSigningCert(string issuer)
    {
        string cacheKey = $"cert-access-token-{issuer}";

        if (!_memoryCache.TryGetValue(cacheKey, out X509Certificate2 cert))
        {
            cert = _secretClient is null
                ? GetSigningCertFromFile(issuer)
                : await GetSigningCertFromKeyVault(issuer);

            MemoryCacheEntryOptions cacheEntryOptions = new MemoryCacheEntryOptions()
           .SetPriority(CacheItemPriority.High)
           .SetAbsoluteExpiration(new TimeSpan(0, 0, _accessTokenSettings.CacheCertLifetimeInSeconds));

            _memoryCache.Set(cacheKey, cert, cacheEntryOptions);
        }

        return cert;
    }

    [ExcludeFromCodeCoverage]
    private async Task<X509Certificate2> GetSigningCertFromKeyVault(string issuer)
    {
        string secretName = $"{issuer}-access-token-public-cert";

        KeyVaultSecret keyVaultSecret = await _secretClient.GetSecretAsync(secretName);

        byte[] certBytes = Convert.FromBase64String(keyVaultSecret.Value);

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(certBytes);
#elif NET8_0
        return new X509Certificate2(certBytes);
#else
#error This code block does not match csproj TargetFrameworks list
#endif
    }

    private X509Certificate2 GetSigningCertFromFile(string issuer)
    {
        string path = _accessTokenSettings.PublicSigningCertificatePath;

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException(
                $"Unable to get the public signing certificate for issuer '{issuer}': no key vault is configured " +
                "(KeyVaultSettings.SecretUri) and no local certificate is configured " +
                $"({nameof(AccessTokenSettings)}.{nameof(AccessTokenSettings.PublicSigningCertificatePath)}).");
        }

        if (path.Contains(IssuerPlaceholder, StringComparison.Ordinal))
        {
            path = path.Replace(IssuerPlaceholder, GetIssuerAsFileName(issuer), StringComparison.Ordinal);
        }

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"No public signing certificate found for issuer '{issuer}'.", path);
        }

        string extension = Path.GetExtension(path);
        if (extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            // Keep only the public part, the private key is not needed to validate tokens.
#if NET9_0_OR_GREATER
            using X509Certificate2 pfx = X509CertificateLoader.LoadPkcs12FromFile(path, null);
            return X509CertificateLoader.LoadCertificate(pfx.RawData);
#elif NET8_0
            using X509Certificate2 pfx = new X509Certificate2(path);
            return new X509Certificate2(pfx.RawData);
#else
#error This code block does not match csproj TargetFrameworks list
#endif
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificateFromFile(path);
#elif NET8_0
        return new X509Certificate2(path);
#else
#error This code block does not match csproj TargetFrameworks list
#endif
    }

    /// <summary>
    /// The issuer comes from the token before its signature is validated, so it must not be able to point
    /// the provider at a file outside the configured folder.
    /// </summary>
    private static string GetIssuerAsFileName(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer)
            || issuer == "."
            || issuer == ".."
            || issuer.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || issuer.IndexOfAny(['/', '\\']) >= 0)
        {
            throw new ArgumentException($"The issuer '{issuer}' can not be used as a file name.", nameof(issuer));
        }

        return issuer;
    }
}
