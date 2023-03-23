using System;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessTokenClient.Configuration;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessTokenClient.Services
{
    /// <summary>
    /// Class to resolve certificate to sign JWT token uses as Access token
    /// </summary>
    public class SigningCredentialsResolver : ISigningCredentialsResolver
    {
        private readonly AccessTokenSettings _accessTokenSettings;
        private static X509SigningCredentials _x509SigningCredentials = null;
        private static readonly object _lockObject = new object();
        private readonly IMemoryCache _memoryCache;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="accessTokenSettings">Access token settings</param>
        public SigningCredentialsResolver(IOptions<AccessTokenSettings> accessTokenSettings, IMemoryCache memoryCache)
        {
            _accessTokenSettings = accessTokenSettings.Value;
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// Find the configured 
        /// </summary>
        /// <returns></returns>
        public SigningCredentials GetSigningCredentials()
        {
            return GetSigningCredentials(_accessTokenSettings);
        }

        /// <summary>
        /// Find the configured 
        /// </summary>
        /// <returns></returns>
        public SigningCredentials GetSigningCredentialsFromKeyVault(ClientSettings clientSettings)
        {
            string certBase64 = GetCertificateAsync(clientSettings.KeyvaultCredentials.KeyVaultUri, clientSettings.KeyvaultCredentials.SecretId).Result;

            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(certBase64), (string)null, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            return new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
        }

        // Static method to make sonarcloud happy (not update static field from instance method)
        private static SigningCredentials GetSigningCredentials(AccessTokenSettings accessTokenSettings)
        {
            if (_x509SigningCredentials == null)
            {
                lock (_lockObject)
                {
                    if (_x509SigningCredentials == null)
                    {
                        string basePath = Directory.GetParent(Directory.GetCurrentDirectory()).FullName;
                        string certPath = basePath + $"{accessTokenSettings.AccessTokenSigningKeysFolder}{accessTokenSettings.AccessTokenSigningCertificateFileName}";
                        X509Certificate2 cert = new X509Certificate2(certPath);
                        _x509SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256);
                    }
                }
            }

            return _x509SigningCredentials;
        }

        private async Task<string> GetCertificateAsync(string vaultUri, string secretId)
        {
            CertificateClient certificateClient = new CertificateClient(new Uri(vaultUri), new DefaultAzureCredential());
            AsyncPageable<CertificateProperties> certificatePropertiesPage = certificateClient.GetPropertiesOfCertificateVersionsAsync(secretId);
            await foreach (CertificateProperties certificateProperties in certificatePropertiesPage)
            {
                if (certificateProperties.Enabled == true &&
                    (certificateProperties.ExpiresOn == null || certificateProperties.ExpiresOn >= DateTime.UtcNow))
                {
                    SecretClient secretClient = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());

                    KeyVaultSecret secret = await secretClient.GetSecretAsync(certificateProperties.Name, certificateProperties.Version);
                    return secret.Value;
                }
            }

            return null;
        }
    }
}
