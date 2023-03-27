using Altinn.Common.AccessToken.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessTokenClient.Services
{
    /// <summary>
    /// Interface to retrive signing credentials for issuer and signing keys for consumer of tokens
    /// </summary>
    public interface ISigningCredentialsResolver
    {
        /// <summary>
        /// Returns certificate to be used for signing a JWT
        /// </summary>
        /// <returns>The signing credentials</returns>
        SigningCredentials GetSigningCredentials();

        /// <summary>
        /// Returns signing credentials to be used for signing a JWT
        /// </summary>
        /// <param name="vaultUri">Uri to key vault</param>
        /// <param name="secretId">secret id</param>
        /// <returns>The signing credentials</returns>
        SigningCredentials GetSigningCredentialsFromKeyVault(string vaultUri, string secretId);
    }
}
