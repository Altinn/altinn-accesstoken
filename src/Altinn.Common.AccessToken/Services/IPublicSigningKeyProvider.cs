using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Services;

/// <summary>
/// Interface for a service that can obtain the public key for the given token issuer.
/// </summary>
public interface IPublicSigningKeyProvider
{
    /// <summary>
    /// Returns the public key for the given issuer as a <see cref="SecurityKey"/>
    /// </summary>
    /// <param name="issuer">The issuer</param>
    /// <returns>The public key of the issuer</returns>
    Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer);
}
