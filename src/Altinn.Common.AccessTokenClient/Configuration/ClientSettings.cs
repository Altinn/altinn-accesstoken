using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Altinn.Common.AccessToken.Configuration
{
    /// <summary>
    /// The key vault settings used to fetch certificate information from key vault
    /// </summary>
    public class ClientSettings
    {
        /// <summary>
        /// The issuer
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The issuer
        /// </summary>
        public string App { get; set; }

        /// <summary>
        /// Client's keyvault credentials
        /// </summary>
        public KeyVaultSettings KeyvaultCredentials { get; set; }
    }

    /// <summary>
    /// Keyvault credentials from cient
    /// </summary>
    public class KeyVaultSettings
    {
        /// <summary>
        /// Uri to keyvault
        /// </summary>
        public string KeyVaultUri { get; set; }

        /// <summary>
        /// Name of the certificate secret
        /// </summary>
        public string SecretId { get; set; }
    }
}
