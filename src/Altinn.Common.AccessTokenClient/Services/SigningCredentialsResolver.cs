using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Altinn.Common.AccessTokenClient.Configuration;
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
        private static X509Certificate2 _cert = null;
        private static DateTime _expiryTime = DateTime.MinValue;
        private static readonly object _lockObject = new object();

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="accessTokenSettings">Access token settings</param>
        public SigningCredentialsResolver(IOptions<AccessTokenSettings> accessTokenSettings)
        {
            _accessTokenSettings = accessTokenSettings.Value;
        }

        /// <summary>
        /// Find the configured 
        /// </summary>
        /// <returns></returns>
        public SigningCredentials GetSigningCredentials()
        {
            return GetSigningCredentials(_accessTokenSettings);
        }

        // Static method to make sonarcloud happy (not update static field from instance method)
        private static SigningCredentials GetSigningCredentials(AccessTokenSettings accessTokenSettings)
        {
            if (_expiryTime > DateTime.UtcNow && _cert != null)
            {
                return new X509SigningCredentials(_cert, SecurityAlgorithms.RsaSha256);
            }

            lock (_lockObject)
            {
                string basePath = Directory.GetParent(Directory.GetCurrentDirectory()).FullName;
                string certPath = basePath + $"{accessTokenSettings.AccessTokenSigningKeysFolder}{accessTokenSettings.AccessTokenSigningCertificateFileName}";
                _cert = new X509Certificate2(certPath);
                _expiryTime = DateTime.UtcNow.AddSeconds(accessTokenSettings.CertificateLifetimeInSeconds - 5); // Set the expiry time to one hour from now
            }

            return new X509SigningCredentials(_cert, SecurityAlgorithms.RsaSha256);
        }
    }
}
