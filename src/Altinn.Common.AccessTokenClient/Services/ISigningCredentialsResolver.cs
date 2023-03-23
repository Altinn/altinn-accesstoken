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
        /// <param name="clientSettings">The client setting</param>
        /// <returns>The signing credentials</returns>
        SigningCredentials GetSigningCredentialsFromKeyVault(ClientSettings clientSettings);
    }
}
